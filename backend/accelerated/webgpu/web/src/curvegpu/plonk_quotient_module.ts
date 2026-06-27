import type { CurveGPUContext, FieldModule, NTTModule, SupportedCurveID } from "./api.js";
import {
  createSimpleStorageBuffer,
  createSimpleStorageBufferFromBytes,
  createSimpleUniformBuffer,
  loadShaderParts,
  readbackSimpleBuffer,
} from "./runtime_common.js";

declare const GPUShaderStage: { COMPUTE: number };

const PLONK_QUOTIENT_BASE_DYNAMIC_VECTOR_COUNT = 5;
const PLONK_QUOTIENT_BASE_STATIC_VECTOR_COUNT = 7;
const PLONK_QUOTIENT_BLIND_COUNT = 4;
const PLONK_QUOTIENT_SCALAR_COUNT = 7;
const PLONK_QUOTIENT_WORKGROUP_SIZE = 64;

const PLONK_QUOTIENT_SHADER_PARTS: Record<SupportedCurveID, readonly string[]> = {
  bn254: [
    "/shaders/curves/bn254/fr_arith.wgsl#section=fr_types",
    "/shaders/curves/bn254/fr_arith.wgsl#section=fr_constants",
    "/shaders/curves/bn254/fr_arith.wgsl#section=fr_core",
    "/shaders/curves/bn254/fr_plonk_quotient.wgsl",
  ],
  bls12_381: [
    "/shaders/curves/bls12_381/fr_arith.wgsl#section=fr_types",
    "/shaders/curves/bls12_381/fr_arith.wgsl#section=fr_constants",
    "/shaders/curves/bls12_381/fr_arith.wgsl#section=fr_core",
    "/shaders/curves/bls12_381/fr_plonk_quotient.wgsl",
  ],
  bls12_377: [
    "/shaders/curves/bls12_377/fr_arith.wgsl#section=fr_types",
    "/shaders/curves/bls12_377/fr_arith.wgsl#section=fr_constants",
    "/shaders/curves/bls12_377/fr_arith.wgsl#section=fr_core",
    "/shaders/curves/bls12_377/fr_plonk_quotient.wgsl",
  ],
};

type PlonkQuotientKernel = {
  device: GPUDevice;
  pipeline: GPUComputePipeline;
  bindGroupLayout: GPUBindGroupLayout;
  workgroupSize: number;
};

export type PlonkTransformAndEvaluateQuotientCosetInput = {
  dynamicValuesPacked: Uint8Array;
  scalingPacked: Uint8Array;
  staticValuesPacked: Uint8Array;
  twiddlesPacked: Uint8Array;
  denominatorsPacked: Uint8Array;
  blindsPacked: Uint8Array;
  scalarsPacked: Uint8Array;
  elementCount: number;
  blindCoeffCount: number;
  commitmentCount: number;
  dynamicTransformCacheKey?: number;
  staticMontCacheKey?: number;
};

export type PlonkTransformAndEvaluateQuotientCosetsInput = PlonkTransformAndEvaluateQuotientCosetInput & {
  staticMontCacheKeysPacked: Uint8Array;
  cosetCount: number;
  auxMontCacheKey?: number;
};

export type PlonkPreloadQuotientStaticAndAuxInput = {
  staticValuesPacked: Uint8Array;
  staticMontCacheKeysPacked: Uint8Array;
  scalingPacked: Uint8Array;
  twiddlesPacked: Uint8Array;
  denominatorsPacked: Uint8Array;
  elementCount: number;
  staticVectorCount: number;
  cosetCount: number;
  auxMontCacheKey: number;
};

export type PlonkQuotientModule = {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  transformAndEvaluateQuotientCoset(input: PlonkTransformAndEvaluateQuotientCosetInput): Promise<Uint8Array>;
  transformAndEvaluateQuotientCosets(input: PlonkTransformAndEvaluateQuotientCosetsInput): Promise<Uint8Array>;
  preloadQuotientStaticAndAux(input: PlonkPreloadQuotientStaticAndAuxInput): Promise<void>;
  prewarmPlonkQuotientEvaluateKernel(commitmentCount?: number): Promise<void>;
};

function cloneBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function repeatPackedVector(value: Uint8Array, count: number): Uint8Array {
  const out = new Uint8Array(value.byteLength * count);
  for (let i = 0; i < count; i += 1) {
    out.set(value, i * value.byteLength);
  }
  return out;
}

function repeatEachPackedVector(values: Uint8Array, vectorBytes: number, repeatCount: number): Uint8Array {
  const vectorCount = values.byteLength / vectorBytes;
  const out = new Uint8Array(values.byteLength * repeatCount);
  for (let i = 0; i < vectorCount; i += 1) {
    const vector = values.subarray(i * vectorBytes, (i + 1) * vectorBytes);
    for (let j = 0; j < repeatCount; j += 1) {
      out.set(vector, (i * repeatCount + j) * vectorBytes);
    }
  }
  return out;
}

function unpackU32LE(bytes: Uint8Array, count: number, label: string): number[] {
  if (bytes.byteLength !== count * 4) {
    throw new Error(`${label}: expected ${count * 4} bytes, got ${bytes.byteLength}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Array.from({ length: count }, (_, i) => view.getUint32(i * 4, true));
}

export function createPlonkQuotientModule(config: {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  fr: FieldModule;
  ntt: NTTModule;
}): PlonkQuotientModule {
  const { context, curve, fr, ntt } = config;
  const quotientKernels = new Map<number, PlonkQuotientKernel>();
  let dynamicTransformCache:
    | {
        key: number;
        elementCount: number;
        dynamicVectorCount: number;
        coeffMont: Uint8Array;
      }
    | null = null;
  const staticMontCache = new Map<
    number,
    {
      elementCount: number;
      staticVectorCount: number;
      mont: Uint8Array;
    }
  >();
  const auxMontCache = new Map<
    number,
    {
      elementCount: number;
      cosetCount: number;
      scalingMont: Uint8Array;
      twiddlesMont: Uint8Array;
      denominatorsMont: Uint8Array;
    }
  >();

  async function getQuotientKernel(commitmentCount: number): Promise<PlonkQuotientKernel> {
    if (!Number.isInteger(commitmentCount) || commitmentCount < 0) {
      throw new Error(`invalid PLONK quotient commitment count ${commitmentCount}`);
    }
    const device = context.device;
    const cached = quotientKernels.get(commitmentCount);
    if (cached?.device === device) {
      return cached;
    }

    const bindGroupLayout = device.createBindGroupLayout({
      label: `plonk-${curve}-quotient-bgl`,
      entries: [
        { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
        { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
        { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
        { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
        { binding: 4, visibility: GPUShaderStage.COMPUTE, buffer: { type: "uniform" } },
      ],
    });
    const pipelineLayout = device.createPipelineLayout({
      label: `plonk-${curve}-quotient-pl`,
      bindGroupLayouts: [bindGroupLayout],
    });
    const code = await loadShaderParts(PLONK_QUOTIENT_SHADER_PARTS[curve]);
    const shader = device.createShaderModule({
      label: `plonk-${curve}-quotient-shader`,
      code,
    });
    const pipeline = await device.createComputePipelineAsync({
      label: `plonk-${curve}-quotient-c${commitmentCount}`,
      layout: pipelineLayout,
      compute: {
        module: shader,
        entryPoint: "fr_plonk_quotient_main",
        constants: {
          WORKGROUP_SIZE: PLONK_QUOTIENT_WORKGROUP_SIZE,
          COMMITMENT_COUNT: commitmentCount,
        },
      },
    });
    const kernel = {
      device,
      pipeline,
      bindGroupLayout,
      workgroupSize: PLONK_QUOTIENT_WORKGROUP_SIZE,
    };
    quotientKernels.set(commitmentCount, kernel);
    return kernel;
  }

  async function runQuotientKernelMont(
    vectorsMontPacked: Uint8Array,
    blindsMontPacked: Uint8Array,
    scalarsMontPacked: Uint8Array,
    elementCount: number,
    blindCoeffCount: number,
    commitmentCount: number,
    cosetCount = 1,
  ) {
    const elementBytes = fr.byteSize;
    const vectorBytes = elementCount * elementBytes;
    const outputBytes = cosetCount * vectorBytes;
    const device = context.device;
    const kernel = await getQuotientKernel(commitmentCount);
    const vectorsBuffer = createSimpleStorageBufferFromBytes(device, "plonk-quotient-vectors", vectorsMontPacked);
    const blindsBuffer = createSimpleStorageBufferFromBytes(device, "plonk-quotient-blinds", blindsMontPacked);
    const scalarsBuffer = createSimpleStorageBufferFromBytes(device, "plonk-quotient-scalars", scalarsMontPacked);
    const outputBuffer = createSimpleStorageBuffer(device, "plonk-quotient-output", outputBytes);
    const paramsBuffer = createSimpleUniformBuffer(
      device,
      "plonk-quotient-params",
      new Uint32Array([elementCount, blindCoeffCount, cosetCount, 0]),
    );

    try {
      const bindGroup = device.createBindGroup({
        label: "plonk-quotient-bg",
        layout: kernel.bindGroupLayout,
        entries: [
          { binding: 0, resource: { buffer: vectorsBuffer } },
          { binding: 1, resource: { buffer: blindsBuffer } },
          { binding: 2, resource: { buffer: scalarsBuffer } },
          { binding: 3, resource: { buffer: outputBuffer } },
          { binding: 4, resource: { buffer: paramsBuffer } },
        ],
      });
      const encoder = device.createCommandEncoder({ label: "plonk-quotient-encoder" });
      const pass = encoder.beginComputePass({ label: "plonk-quotient-pass" });
      pass.setPipeline(kernel.pipeline);
      pass.setBindGroup(0, bindGroup);
      pass.dispatchWorkgroups(Math.ceil(elementCount / kernel.workgroupSize), cosetCount, 1);
      pass.end();
      device.queue.submit([encoder.finish()]);
      await device.queue.onSubmittedWorkDone();
      return await readbackSimpleBuffer(device, outputBuffer, outputBytes, "plonk-quotient");
    } finally {
      vectorsBuffer.destroy();
      blindsBuffer.destroy();
      scalarsBuffer.destroy();
      outputBuffer.destroy();
      paramsBuffer.destroy();
    }
  }

  async function transformAndEvaluateQuotientCoset(input: PlonkTransformAndEvaluateQuotientCosetInput): Promise<Uint8Array> {
    const {
      dynamicValuesPacked,
      scalingPacked,
      staticValuesPacked,
      twiddlesPacked,
      denominatorsPacked,
      blindsPacked,
      scalarsPacked,
      elementCount,
      blindCoeffCount,
      commitmentCount,
      dynamicTransformCacheKey = 0,
      staticMontCacheKey = 0,
    } = input;
    const elementBytes = fr.byteSize;
    const vectorBytes = elementCount * elementBytes;
    if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
      throw new Error(`invalid PLONK quotient evaluate element count ${elementCount}`);
    }
    if (!Number.isInteger(blindCoeffCount) || blindCoeffCount < 0) {
      throw new Error(`invalid PLONK quotient blind coefficient count ${blindCoeffCount}`);
    }
    if (!Number.isInteger(commitmentCount) || commitmentCount < 0) {
      throw new Error(`invalid PLONK quotient commitment count ${commitmentCount}`);
    }

    const dynamicVectorCount = PLONK_QUOTIENT_BASE_DYNAMIC_VECTOR_COUNT + commitmentCount;
    const staticVectorCount = PLONK_QUOTIENT_BASE_STATIC_VECTOR_COUNT + commitmentCount;
    const vectorCount = dynamicVectorCount + staticVectorCount + 2;
    const expectedDynamicBytes = dynamicVectorCount * vectorBytes;
    const canReuseDynamicCache =
      dynamicTransformCacheKey > 0 &&
      dynamicTransformCache?.key === dynamicTransformCacheKey &&
      dynamicTransformCache.elementCount === elementCount &&
      dynamicTransformCache.dynamicVectorCount === dynamicVectorCount;
    const cachedDynamicCoeffMont = canReuseDynamicCache ? dynamicTransformCache?.coeffMont : undefined;
    if (dynamicValuesPacked.byteLength !== expectedDynamicBytes && !(dynamicValuesPacked.byteLength === 0 && canReuseDynamicCache)) {
      throw new Error(
        `PLONK quotient transform/evaluate expected ${expectedDynamicBytes} dynamic bytes, got ${dynamicValuesPacked.byteLength}`,
      );
    }
    if (scalingPacked.byteLength !== vectorBytes) {
      throw new Error(`PLONK quotient transform/evaluate expected ${vectorBytes} scaling bytes, got ${scalingPacked.byteLength}`);
    }
    const expectedStaticBytes = staticVectorCount * vectorBytes;
    const cachedStatic = staticMontCacheKey > 0 ? staticMontCache.get(staticMontCacheKey) : undefined;
    const canReuseStaticCache =
      staticMontCacheKey > 0 &&
      cachedStatic?.elementCount === elementCount &&
      cachedStatic.staticVectorCount === staticVectorCount;
    if (staticValuesPacked.byteLength !== expectedStaticBytes && !(staticValuesPacked.byteLength === 0 && canReuseStaticCache)) {
      throw new Error(
        `PLONK quotient transform/evaluate expected ${expectedStaticBytes} static bytes, got ${staticValuesPacked.byteLength}`,
      );
    }
    if (twiddlesPacked.byteLength !== vectorBytes) {
      throw new Error(`PLONK quotient transform/evaluate expected ${vectorBytes} twiddle bytes, got ${twiddlesPacked.byteLength}`);
    }
    if (denominatorsPacked.byteLength !== vectorBytes) {
      throw new Error(`PLONK quotient transform/evaluate expected ${vectorBytes} denominator bytes, got ${denominatorsPacked.byteLength}`);
    }
    const blindBytes = PLONK_QUOTIENT_BLIND_COUNT * blindCoeffCount * elementBytes;
    if (blindsPacked.byteLength !== blindBytes) {
      throw new Error(`PLONK quotient transform/evaluate expected ${blindBytes} blinding bytes, got ${blindsPacked.byteLength}`);
    }
    const scalarBytes = PLONK_QUOTIENT_SCALAR_COUNT * elementBytes;
    if (scalarsPacked.byteLength !== scalarBytes) {
      throw new Error(`PLONK quotient transform/evaluate expected ${scalarBytes} scalar bytes, got ${scalarsPacked.byteLength}`);
    }

    const vectorsMontPacked = new Uint8Array(vectorCount * vectorBytes);
    const dynamicCoeffMont =
      cachedDynamicCoeffMont
        ? cachedDynamicCoeffMont
        : await (async (): Promise<Uint8Array> => {
            const dynamicMont = await fr.toMontgomeryPacked(cloneBytes(dynamicValuesPacked));
            const coeffMont = await ntt.inversePackedMontBatch(dynamicMont, elementCount, dynamicVectorCount);
            if (dynamicTransformCacheKey > 0) {
              dynamicTransformCache = {
                key: dynamicTransformCacheKey,
                elementCount,
                dynamicVectorCount,
                coeffMont,
              };
            }
            return coeffMont;
          })();
    const scalingMont = await fr.toMontgomeryPacked(cloneBytes(scalingPacked));
    const scalingMontBatch = repeatPackedVector(scalingMont, dynamicVectorCount);
    const shiftedCoeffMont = await fr.mulPackedMont(dynamicCoeffMont, scalingMontBatch);
    vectorsMontPacked.set(await ntt.forwardPackedMontBatch(shiftedCoeffMont, elementCount, dynamicVectorCount));

    const cachedStaticMont = canReuseStaticCache ? cachedStatic?.mont : undefined;
    const staticMontPromise = cachedStaticMont
      ? Promise.resolve(cachedStaticMont)
      : fr.toMontgomeryPacked(cloneBytes(staticValuesPacked)).then((mont) => {
          if (staticMontCacheKey > 0) {
            staticMontCache.set(staticMontCacheKey, {
              elementCount,
              staticVectorCount,
              mont,
            });
          }
          return mont;
        });
    const [staticMont, twiddlesMont, denominatorsMont, blindsMont, scalarsMont] = await Promise.all([
      staticMontPromise,
      fr.toMontgomeryPacked(cloneBytes(twiddlesPacked)),
      fr.toMontgomeryPacked(cloneBytes(denominatorsPacked)),
      fr.toMontgomeryPacked(cloneBytes(blindsPacked)),
      fr.toMontgomeryPacked(cloneBytes(scalarsPacked)),
    ]);

    vectorsMontPacked.set(staticMont, dynamicVectorCount * vectorBytes);
    vectorsMontPacked.set(twiddlesMont, (dynamicVectorCount + staticVectorCount) * vectorBytes);
    vectorsMontPacked.set(denominatorsMont, (dynamicVectorCount + staticVectorCount + 1) * vectorBytes);
    return runQuotientKernelMont(vectorsMontPacked, blindsMont, scalarsMont, elementCount, blindCoeffCount, commitmentCount);
  }

  async function transformAndEvaluateQuotientCosets(input: PlonkTransformAndEvaluateQuotientCosetsInput): Promise<Uint8Array> {
    const {
      dynamicValuesPacked,
      scalingPacked,
      staticValuesPacked,
      staticMontCacheKeysPacked,
      twiddlesPacked,
      denominatorsPacked,
      blindsPacked,
      scalarsPacked,
      elementCount,
      blindCoeffCount,
      commitmentCount,
      dynamicTransformCacheKey = 0,
      cosetCount,
      auxMontCacheKey = 0,
    } = input;
    const elementBytes = fr.byteSize;
    const vectorBytes = elementCount * elementBytes;
    if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
      throw new Error(`invalid PLONK quotient evaluate element count ${elementCount}`);
    }
    if (!Number.isInteger(blindCoeffCount) || blindCoeffCount < 0) {
      throw new Error(`invalid PLONK quotient blind coefficient count ${blindCoeffCount}`);
    }
    if (!Number.isInteger(commitmentCount) || commitmentCount < 0) {
      throw new Error(`invalid PLONK quotient commitment count ${commitmentCount}`);
    }
    if (!Number.isInteger(cosetCount) || cosetCount <= 0) {
      throw new Error(`invalid PLONK quotient coset count ${cosetCount}`);
    }
    if (!Number.isInteger(auxMontCacheKey) || auxMontCacheKey < 0) {
      throw new Error(`invalid PLONK quotient aux cache key ${auxMontCacheKey}`);
    }

    const dynamicVectorCount = PLONK_QUOTIENT_BASE_DYNAMIC_VECTOR_COUNT + commitmentCount;
    const staticVectorCount = PLONK_QUOTIENT_BASE_STATIC_VECTOR_COUNT + commitmentCount;
    const vectorCount = dynamicVectorCount + staticVectorCount + 2;
    const expectedDynamicBytes = dynamicVectorCount * vectorBytes;
    if (dynamicValuesPacked.byteLength !== expectedDynamicBytes) {
      throw new Error(
        `PLONK quotient cosets expected ${expectedDynamicBytes} dynamic bytes, got ${dynamicValuesPacked.byteLength}`,
      );
    }
    const cachedAux = auxMontCacheKey > 0 ? auxMontCache.get(auxMontCacheKey) : undefined;
    const canReuseAuxCache =
      scalingPacked.byteLength === 0 &&
      twiddlesPacked.byteLength === 0 &&
      denominatorsPacked.byteLength === 0 &&
      cachedAux !== undefined &&
      cachedAux.elementCount === elementCount &&
      cachedAux.cosetCount === cosetCount;
    if (scalingPacked.byteLength !== cosetCount * vectorBytes && !canReuseAuxCache) {
      throw new Error(`PLONK quotient cosets expected ${cosetCount * vectorBytes} scaling bytes, got ${scalingPacked.byteLength}`);
    }
    const expectedStaticBytes = cosetCount * staticVectorCount * vectorBytes;
    const staticMontCacheKeys = unpackU32LE(staticMontCacheKeysPacked, cosetCount, "PLONK quotient static cache keys");
    const canReuseStaticCache =
      staticValuesPacked.byteLength === 0 &&
      staticMontCacheKeys.every((key) => {
        const cached = key > 0 ? staticMontCache.get(key) : undefined;
        return cached?.elementCount === elementCount && cached.staticVectorCount === staticVectorCount;
      });
    if (staticValuesPacked.byteLength !== expectedStaticBytes && !canReuseStaticCache) {
      throw new Error(
        `PLONK quotient cosets expected ${expectedStaticBytes} static bytes, got ${staticValuesPacked.byteLength}`,
      );
    }
    if (twiddlesPacked.byteLength !== vectorBytes && !canReuseAuxCache) {
      throw new Error(`PLONK quotient cosets expected ${vectorBytes} twiddle bytes, got ${twiddlesPacked.byteLength}`);
    }
    if (denominatorsPacked.byteLength !== cosetCount * vectorBytes && !canReuseAuxCache) {
      throw new Error(
        `PLONK quotient cosets expected ${cosetCount * vectorBytes} denominator bytes, got ${denominatorsPacked.byteLength}`,
      );
    }
    const blindBytes = PLONK_QUOTIENT_BLIND_COUNT * blindCoeffCount * elementBytes;
    if (blindsPacked.byteLength !== cosetCount * blindBytes) {
      throw new Error(`PLONK quotient cosets expected ${cosetCount * blindBytes} blinding bytes, got ${blindsPacked.byteLength}`);
    }
    const scalarBytes = PLONK_QUOTIENT_SCALAR_COUNT * elementBytes;
    if (scalarsPacked.byteLength !== cosetCount * scalarBytes) {
      throw new Error(`PLONK quotient cosets expected ${cosetCount * scalarBytes} scalar bytes, got ${scalarsPacked.byteLength}`);
    }

    const dynamicMont = await fr.toMontgomeryPacked(cloneBytes(dynamicValuesPacked));
    const dynamicCoeffMont = await ntt.inversePackedMontBatch(dynamicMont, elementCount, dynamicVectorCount);
    if (dynamicTransformCacheKey > 0) {
      dynamicTransformCache = {
        key: dynamicTransformCacheKey,
        elementCount,
        dynamicVectorCount,
        coeffMont: dynamicCoeffMont,
      };
    }
    let scalingMont: Uint8Array;
    let twiddlesMont: Uint8Array;
    let denominatorsMont: Uint8Array;
    if (canReuseAuxCache) {
      if (!cachedAux) {
        throw new Error(`PLONK quotient missing aux cache key ${auxMontCacheKey}`);
      }
      ({ scalingMont, twiddlesMont, denominatorsMont } = cachedAux);
    } else {
      [scalingMont, twiddlesMont, denominatorsMont] = await Promise.all([
        fr.toMontgomeryPacked(cloneBytes(scalingPacked)),
        fr.toMontgomeryPacked(cloneBytes(twiddlesPacked)),
        fr.toMontgomeryPacked(cloneBytes(denominatorsPacked)),
      ]);
      if (auxMontCacheKey > 0) {
        auxMontCache.set(auxMontCacheKey, {
          elementCount,
          cosetCount,
          scalingMont: cloneBytes(scalingMont),
          twiddlesMont: cloneBytes(twiddlesMont),
          denominatorsMont: cloneBytes(denominatorsMont),
        });
      }
    }
    const shiftedCoeffMont = await fr.mulPackedMont(
      repeatPackedVector(dynamicCoeffMont, cosetCount),
      repeatEachPackedVector(scalingMont, vectorBytes, dynamicVectorCount),
    );
    const dynamicCosetsMont = await ntt.forwardPackedMontBatch(shiftedCoeffMont, elementCount, dynamicVectorCount * cosetCount);

    const staticMont = canReuseStaticCache
      ? (() => {
          const out = new Uint8Array(cosetCount * staticVectorCount * vectorBytes);
          for (let i = 0; i < cosetCount; i += 1) {
            const cached = staticMontCache.get(staticMontCacheKeys[i]);
            if (!cached) {
              throw new Error(`PLONK quotient missing static cache key ${staticMontCacheKeys[i]}`);
            }
            out.set(cached.mont, i * staticVectorCount * vectorBytes);
          }
          return out;
        })()
      : await fr.toMontgomeryPacked(cloneBytes(staticValuesPacked));
    if (!canReuseStaticCache) {
      for (let i = 0; i < cosetCount; i += 1) {
        const key = staticMontCacheKeys[i];
        if (key > 0) {
          const start = i * staticVectorCount * vectorBytes;
          staticMontCache.set(key, {
            elementCount,
            staticVectorCount,
            mont: cloneBytes(staticMont.subarray(start, start + staticVectorCount * vectorBytes)),
          });
        }
      }
    }

    const [blindsMont, scalarsMont] = await Promise.all([
      fr.toMontgomeryPacked(cloneBytes(blindsPacked)),
      fr.toMontgomeryPacked(cloneBytes(scalarsPacked)),
    ]);

    const vectorsMontPacked = new Uint8Array(cosetCount * vectorCount * vectorBytes);
    for (let i = 0; i < cosetCount; i += 1) {
      const vectorsStart = i * vectorCount * vectorBytes;
      const dynamicStart = i * dynamicVectorCount * vectorBytes;
      vectorsMontPacked.set(
        dynamicCosetsMont.subarray(dynamicStart, dynamicStart + dynamicVectorCount * vectorBytes),
        vectorsStart,
      );
      const staticStart = i * staticVectorCount * vectorBytes;
      vectorsMontPacked.set(
        staticMont.subarray(staticStart, staticStart + staticVectorCount * vectorBytes),
        vectorsStart + dynamicVectorCount * vectorBytes,
      );
      vectorsMontPacked.set(twiddlesMont, vectorsStart + (dynamicVectorCount + staticVectorCount) * vectorBytes);
      const denominatorStart = i * vectorBytes;
      vectorsMontPacked.set(
        denominatorsMont.subarray(denominatorStart, denominatorStart + vectorBytes),
        vectorsStart + (dynamicVectorCount + staticVectorCount + 1) * vectorBytes,
      );
    }
    return runQuotientKernelMont(
      vectorsMontPacked,
      blindsMont,
      scalarsMont,
      elementCount,
      blindCoeffCount,
      commitmentCount,
      cosetCount,
    );
  }

  async function preloadQuotientStaticAndAux(input: PlonkPreloadQuotientStaticAndAuxInput): Promise<void> {
    const {
      staticValuesPacked,
      staticMontCacheKeysPacked,
      scalingPacked,
      twiddlesPacked,
      denominatorsPacked,
      elementCount,
      staticVectorCount,
      cosetCount,
      auxMontCacheKey,
    } = input;
    const elementBytes = fr.byteSize;
    const vectorBytes = elementCount * elementBytes;
    if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
      throw new Error(`invalid PLONK quotient preload element count ${elementCount}`);
    }
    if (!Number.isInteger(staticVectorCount) || staticVectorCount <= 0) {
      throw new Error(`invalid PLONK quotient preload static vector count ${staticVectorCount}`);
    }
    if (!Number.isInteger(cosetCount) || cosetCount <= 0) {
      throw new Error(`invalid PLONK quotient preload coset count ${cosetCount}`);
    }
    if (!Number.isInteger(auxMontCacheKey) || auxMontCacheKey <= 0) {
      throw new Error(`invalid PLONK quotient preload aux cache key ${auxMontCacheKey}`);
    }

    const expectedStaticBytes = cosetCount * staticVectorCount * vectorBytes;
    if (staticValuesPacked.byteLength !== expectedStaticBytes) {
      throw new Error(`PLONK quotient preload expected ${expectedStaticBytes} static bytes, got ${staticValuesPacked.byteLength}`);
    }
    if (scalingPacked.byteLength !== cosetCount * vectorBytes) {
      throw new Error(`PLONK quotient preload expected ${cosetCount * vectorBytes} scaling bytes, got ${scalingPacked.byteLength}`);
    }
    if (twiddlesPacked.byteLength !== vectorBytes) {
      throw new Error(`PLONK quotient preload expected ${vectorBytes} twiddle bytes, got ${twiddlesPacked.byteLength}`);
    }
    if (denominatorsPacked.byteLength !== cosetCount * vectorBytes) {
      throw new Error(
        `PLONK quotient preload expected ${cosetCount * vectorBytes} denominator bytes, got ${denominatorsPacked.byteLength}`,
      );
    }

    const staticMontCacheKeys = unpackU32LE(staticMontCacheKeysPacked, cosetCount, "PLONK quotient preload static cache keys");
    const [staticMont, scalingMont, twiddlesMont, denominatorsMont] = await Promise.all([
      fr.toMontgomeryPacked(cloneBytes(staticValuesPacked)),
      fr.toMontgomeryPacked(cloneBytes(scalingPacked)),
      fr.toMontgomeryPacked(cloneBytes(twiddlesPacked)),
      fr.toMontgomeryPacked(cloneBytes(denominatorsPacked)),
    ]);

    for (let i = 0; i < cosetCount; i += 1) {
      const key = staticMontCacheKeys[i];
      if (key <= 0) {
        throw new Error(`invalid PLONK quotient preload static cache key ${key}`);
      }
      const start = i * staticVectorCount * vectorBytes;
      staticMontCache.set(key, {
        elementCount,
        staticVectorCount,
        mont: cloneBytes(staticMont.subarray(start, start + staticVectorCount * vectorBytes)),
      });
    }
    auxMontCache.set(auxMontCacheKey, {
      elementCount,
      cosetCount,
      scalingMont: cloneBytes(scalingMont),
      twiddlesMont: cloneBytes(twiddlesMont),
      denominatorsMont: cloneBytes(denominatorsMont),
    });
  }

  return {
    context,
    curve,
    transformAndEvaluateQuotientCoset,
    transformAndEvaluateQuotientCosets,
    preloadQuotientStaticAndAux,
    async prewarmPlonkQuotientEvaluateKernel(commitmentCount = 0): Promise<void> {
      await getQuotientKernel(commitmentCount);
    },
  };
}
