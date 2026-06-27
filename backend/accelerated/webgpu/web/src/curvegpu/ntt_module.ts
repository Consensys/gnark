import type { CurveGPUContext, CurveGPUElementBytes, FieldModule, Groth16QuotientModule, NTTModule, SupportedCurveID } from "./api.js";
import type { SimpleKernel } from "./runtime_common.js";
import {
  createSimpleBindGroup,
  createSimpleStorageBuffer,
  createSimpleStorageBufferFromBytes,
  createSimpleUniformBuffer,
  ensureByteLength,
  lazyAsync,
  packElementBatch,
  readbackSimpleBuffer,
  runSimpleKernel,
  submitSimpleKernel,
  unpackElementBatch,
} from "./runtime_common.js";
import { fetchJSON } from "./browser_utils.js";
import { hexToBytesLE } from "./encoding.js";

declare const GPUBufferUsage: {
  STORAGE: number;
  COPY_DST: number;
  COPY_SRC: number;
};

const VECTOR_OP_MUL_FACTORS = 3;
const VECTOR_OP_BIT_REVERSE_COPY = 4;
const FIELD_OP_SUB = 4;
const FIELD_OP_MUL = 9;
const FIELD_OP_TO_MONT = 11;
const FIELD_OP_FROM_MONT = 12;
type DomainMetadata = {
  log_n: number;
  size: number;
  omega_hex: string;
  omega_inv_hex: string;
  cardinality_inv_hex: string;
  coset_gen_hex: string;
  coset_gen_inv_hex: string;
  coset_den_inv_hex: string;
};

type DomainMetadataFile = {
  domains: DomainMetadata[];
};

type PreparedDomain = {
  forwardStageMont: Uint8Array[];
  inverseStageMont: Uint8Array[];
  inverseScaleMont: Uint8Array;
  inverseScaleFactorsPackedMont: Uint8Array;
  cosetPowersPackedMont: Uint8Array;
  inverseCosetPowersPackedMont: Uint8Array;
  cosetDenInvMont: Uint8Array;
  cosetDenInvFactorsPackedMont: Uint8Array;
};

function hexToBigInt(hex: string): bigint {
  return BigInt(`0x${hex}`);
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let acc = base % mod;
  let power = exp;
  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = (result * acc) % mod;
    }
    acc = (acc * acc) % mod;
    power >>= 1n;
  }
  return result;
}

function bigIntToBytesLE(value: bigint, byteSize: number): Uint8Array {
  const out = new Uint8Array(byteSize);
  let x = value;
  for (let i = 0; i < byteSize; i += 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function ensurePackedElements(bytes: Uint8Array, elementBytes: number, label: string): number {
  if (bytes.byteLength % elementBytes !== 0) {
    throw new Error(`${label}: expected a multiple of ${elementBytes} bytes, got ${bytes.byteLength}`);
  }
  return bytes.byteLength / elementBytes;
}

function repeatPackedElement(value: Uint8Array, count: number): Uint8Array {
  const out = new Uint8Array(value.byteLength * count);
  for (let i = 0; i < count; i += 1) {
    out.set(value, i * value.byteLength);
  }
  return out;
}

function repeatPackedVector(value: Uint8Array, count: number): Uint8Array {
  const out = new Uint8Array(value.byteLength * count);
  for (let i = 0; i < count; i += 1) {
    out.set(value, i * value.byteLength);
  }
  return out;
}

function buildPowerVectorPackedRegular(base: bigint, count: number, modulus: bigint, elementBytes: number): Uint8Array {
  const out = new Uint8Array(count * elementBytes);
  let acc = 1n;
  for (let i = 0; i < count; i += 1) {
    out.set(bigIntToBytesLE(acc, elementBytes), i * elementBytes);
    acc = (acc * base) % modulus;
  }
  return out;
}

function buildRegularStageElements(domain: DomainMetadata, inverse: boolean, modulus: bigint, elementBytes: number): Uint8Array[][] {
  const logN = domain.log_n;
  const omega = hexToBigInt(inverse ? domain.omega_inv_hex : domain.omega_hex);
  const stages: Uint8Array[][] = [];
  for (let stage = 1; stage <= logN; stage += 1) {
    const m = 1 << (stage - 1);
    const exponentShift = BigInt(logN - stage);
    const step = modPow(omega, 1n << exponentShift, modulus);
    const stageElements: Uint8Array[] = [];
    let acc = 1n;
    for (let i = 0; i < m; i += 1) {
      stageElements.push(bigIntToBytesLE(acc, elementBytes));
      acc = (acc * step) % modulus;
    }
    stages.push(stageElements);
  }
  return stages;
}

export function createNTTModule(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    vectorKernel: SimpleKernel;
    fieldKernel: SimpleKernel;
    nttKernel: SimpleKernel;
    domainPath: string;
    modulusHex: string;
  },
  fr: FieldModule,
): NTTModule & Groth16QuotientModule {
  const { curve, vectorKernel, fieldKernel, nttKernel, domainPath, modulusHex } = options;
  const label = `${curve}-fr-ntt`;
  const elementBytes = fr.byteSize;

  const getVectorKernel = lazyAsync(async () => vectorKernel);
  const getFieldKernel = lazyAsync(async () => fieldKernel);
  const getNTTKernel = lazyAsync(async () => nttKernel);
  const getDomains = lazyAsync(async () => fetchJSON<DomainMetadataFile>(domainPath));
  const domainCache = new Map<number, Promise<PreparedDomain>>();
  const modulus = BigInt(modulusHex);

  async function prepareDomain(size: number): Promise<PreparedDomain> {
    const cached = domainCache.get(size);
    if (cached) {
      return cached;
    }
    const promise = (async (): Promise<PreparedDomain> => {
      const file = await getDomains();
      const domain = file.domains.find((item) => item.size === size);
      if (!domain) {
        throw new Error(`${label}: missing domain metadata for size ${size}`);
      }
      const forwardStageRegular = buildRegularStageElements(domain, false, modulus, elementBytes);
      const inverseStageRegular = buildRegularStageElements(domain, true, modulus, elementBytes);
      const forwardStageMont = await Promise.all(
        forwardStageRegular.map(async (stage) =>
          fr.toMontgomeryPacked(packElementBatch(stage, elementBytes, `${label}.forwardStageRegular`)),
        ),
      );
      const inverseStageMont = await Promise.all(
        inverseStageRegular.map(async (stage) =>
          fr.toMontgomeryPacked(packElementBatch(stage, elementBytes, `${label}.inverseStageRegular`)),
        ),
      );
      const inverseScaleMont = await fr.toMontgomery(hexToBytesLE(domain.cardinality_inv_hex, elementBytes));
      const cosetPowersPackedMont = await fr.toMontgomeryPacked(
        buildPowerVectorPackedRegular(hexToBigInt(domain.coset_gen_hex), size, modulus, elementBytes),
      );
      const inverseCosetPowersPackedMont = await fr.toMontgomeryPacked(
        buildPowerVectorPackedRegular(hexToBigInt(domain.coset_gen_inv_hex), size, modulus, elementBytes),
      );
      const cosetDenInvMont = await fr.toMontgomery(hexToBytesLE(domain.coset_den_inv_hex, elementBytes));
      return {
        forwardStageMont,
        inverseStageMont,
        inverseScaleMont,
        inverseScaleFactorsPackedMont: repeatPackedElement(inverseScaleMont, size),
        cosetPowersPackedMont,
        inverseCosetPowersPackedMont,
        cosetDenInvMont,
        cosetDenInvFactorsPackedMont: repeatPackedElement(cosetDenInvMont, size),
      };
    })();
    domainCache.set(size, promise);
    return promise;
  }

  async function runVectorOpPacked(opcode: number, valuesPacked: Uint8Array, factorsPacked?: Uint8Array, logCount = 0): Promise<Uint8Array> {
    const count = ensurePackedElements(valuesPacked, elementBytes, `${label}.valuesPacked`);
    const kernel = await getVectorKernel();
    const factorBytes = factorsPacked ?? new Uint8Array(valuesPacked.byteLength);
    if (factorBytes.byteLength !== valuesPacked.byteLength) {
      throw new Error(`${label}.factorsPacked: expected ${valuesPacked.byteLength} bytes, got ${factorBytes.byteLength}`);
    }
    return runSimpleKernel({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-vector-packed-${opcode}`,
      inputA: valuesPacked,
      inputB: factorBytes,
      outputBytes: count * elementBytes,
      uniformWords: Uint32Array.from([count, opcode, logCount, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
  }

  async function runFieldOpPacked(opcode: number, inputA: Uint8Array, inputB: Uint8Array): Promise<Uint8Array> {
    const count = ensurePackedElements(inputA, elementBytes, `${label}.fieldPackedA`);
    if (inputB.byteLength !== inputA.byteLength) {
      throw new Error(`${label}.fieldPackedB: expected ${inputA.byteLength} bytes, got ${inputB.byteLength}`);
    }
    const kernel = await getFieldKernel();
    return runSimpleKernel({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-field-packed-${opcode}`,
      inputA,
      inputB,
      outputBytes: count * elementBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
  }

  async function runPipelinePackedBatch(options: {
    values: Uint8Array;
    vectorSize: number;
    vectorCount: number;
    inverse: boolean;
    inputRegular: boolean;
    outputRegular: boolean;
    inputBitReversed?: boolean;
    inverseCoset?: boolean;
  }): Promise<Uint8Array> {
    const {
      values,
      vectorSize,
      vectorCount,
      inverse,
      inputRegular,
      outputRegular,
      inputBitReversed = false,
      inverseCoset = false,
    } = options;
    if (inverseCoset && !inverse) {
      throw new Error(`${label}: inverseCoset requires inverse NTT`);
    }
    if (!Number.isInteger(vectorSize) || vectorSize <= 0 || (vectorSize & (vectorSize - 1)) !== 0) {
      throw new Error(`${label}: NTT input length must be a non-zero power of two`);
    }
    if (!Number.isInteger(vectorCount) || vectorCount <= 0) {
      throw new Error(`${label}: NTT vector count must be positive`);
    }
    const totalCount = ensurePackedElements(values, elementBytes, `${label}.pipeline.values`);
    const expectedCount = vectorSize * vectorCount;
    if (totalCount !== expectedCount) {
      throw new Error(`${label}: expected ${expectedCount} packed elements, got ${totalCount}`);
    }

    const totalBytes = totalCount * elementBytes;
    const domain = await prepareDomain(vectorSize);
    const [fieldKernel, vectorKernel, nttKernel] = await Promise.all([getFieldKernel(), getVectorKernel(), getNTTKernel()]);
    const zeroAux = createSimpleStorageBufferFromBytes(
      context.device,
      `${label}-zero-aux`,
      new Uint8Array(4),
      GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
    );
    let current = createSimpleStorageBufferFromBytes(
      context.device,
      `${label}-state-a`,
      values,
      GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST | GPUBufferUsage.COPY_SRC,
    );
    let next = createSimpleStorageBuffer(
      context.device,
      `${label}-state-b`,
      totalBytes,
      GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST | GPUBufferUsage.COPY_SRC,
    );

    const dispatch = async (
      kernel: SimpleKernel,
      inputA: GPUBuffer,
      inputB: GPUBuffer,
      output: GPUBuffer,
      uniformWords: Uint32Array,
      opLabel: string,
    ): Promise<void> => {
      const uniform = createSimpleUniformBuffer(context.device, `${opLabel}-params`, uniformWords);
      try {
        const bindGroup = createSimpleBindGroup(context.device, kernel, `${opLabel}-bg`, inputA, inputB, output, uniform);
        await submitSimpleKernel(context.device, kernel, bindGroup, Math.ceil(totalCount / kernel.workgroupSize), opLabel);
      } finally {
        uniform.destroy();
      }
    };

    const dispatchNTTStage = async (
      inputA: GPUBuffer,
      twiddles: GPUBuffer,
      output: GPUBuffer,
      uniformWords: Uint32Array,
      opLabel: string,
    ): Promise<void> => {
      const uniform = createSimpleUniformBuffer(context.device, `${opLabel}-params`, uniformWords);
      try {
        const bindGroup = createSimpleBindGroup(context.device, nttKernel, `${opLabel}-bg`, inputA, twiddles, output, uniform);
        const encoder = context.device.createCommandEncoder({ label: `${opLabel}-encoder` });
        const pass = encoder.beginComputePass({ label: `${opLabel}-pass` });
        pass.setPipeline(nttKernel.pipeline);
        pass.setBindGroup(0, bindGroup);
        pass.dispatchWorkgroups(Math.ceil((vectorSize / 2) / nttKernel.workgroupSize), vectorCount, 1);
        pass.end();
        context.device.queue.submit([encoder.finish()]);
        await context.device.queue.onSubmittedWorkDone();
      } finally {
        uniform.destroy();
      }
    };

    const swap = (): void => {
      const tmp = current;
      current = next;
      next = tmp;
    };

    try {
      if (inputRegular) {
        await dispatch(
          fieldKernel,
          current,
          zeroAux,
          next,
          Uint32Array.from([totalCount, FIELD_OP_TO_MONT, 0, 0, 0, 0, 0, 0]),
          `${label}-to-mont`,
        );
        swap();
      }

      if (!inputBitReversed) {
        await dispatch(
          vectorKernel,
          current,
          zeroAux,
          next,
          Uint32Array.from([totalCount, VECTOR_OP_BIT_REVERSE_COPY, Math.round(Math.log2(vectorSize)), vectorSize, 0, 0, 0, 0]),
          `${label}-bit-reverse`,
        );
        swap();
      }

      const stages = inverse ? domain.inverseStageMont : domain.forwardStageMont;
      for (let stage = 0; stage < stages.length; stage += 1) {
        const twiddleBuffer = createSimpleStorageBufferFromBytes(
          context.device,
          `${label}-twiddles-${stage}`,
          stages[stage],
          GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
        );
        try {
          await dispatchNTTStage(
            current,
            twiddleBuffer,
            next,
            Uint32Array.from([vectorSize, 1 << stage, vectorCount, inverse ? 1 : 0, 0, 0, 0, 0]),
            `${label}-stage-${stage}-${inverse ? "inv" : "fwd"}`,
          );
        } finally {
          twiddleBuffer.destroy();
        }
        swap();
      }

      if (inverse) {
        const inverseScaleFactorsPackedMont =
          vectorCount === 1 ? domain.inverseScaleFactorsPackedMont : repeatPackedVector(domain.inverseScaleFactorsPackedMont, vectorCount);
        const factorBuffer = createSimpleStorageBufferFromBytes(
          context.device,
          `${label}-inverse-scale`,
          inverseScaleFactorsPackedMont,
          GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
        );
        try {
          await dispatch(
            vectorKernel,
            current,
            factorBuffer,
            next,
            Uint32Array.from([totalCount, VECTOR_OP_MUL_FACTORS, 0, 0, 0, 0, 0, 0]),
            `${label}-inverse-scale`,
          );
        } finally {
          factorBuffer.destroy();
        }
        swap();
      }

      if (inverseCoset) {
        const inverseCosetPowersPackedMont =
          vectorCount === 1 ? domain.inverseCosetPowersPackedMont : repeatPackedVector(domain.inverseCosetPowersPackedMont, vectorCount);
        const factorBuffer = createSimpleStorageBufferFromBytes(
          context.device,
          `${label}-inverse-coset-scale`,
          inverseCosetPowersPackedMont,
          GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
        );
        try {
          await dispatch(
            vectorKernel,
            current,
            factorBuffer,
            next,
            Uint32Array.from([totalCount, VECTOR_OP_MUL_FACTORS, 0, 0, 0, 0, 0, 0]),
            `${label}-inverse-coset-scale`,
          );
        } finally {
          factorBuffer.destroy();
        }
        swap();
      }

      if (outputRegular) {
        await dispatch(
          fieldKernel,
          current,
          zeroAux,
          next,
          Uint32Array.from([totalCount, FIELD_OP_FROM_MONT, 0, 0, 0, 0, 0, 0]),
          `${label}-from-mont`,
        );
        swap();
      }

      return await readbackSimpleBuffer(context.device, current, totalBytes, `${label}-pipeline`);
    } finally {
      zeroAux.destroy();
      current.destroy();
      next.destroy();
    }
  }

  async function runPipelinePacked(options: {
    values: Uint8Array;
    inverse: boolean;
    inputRegular: boolean;
    outputRegular: boolean;
    inputBitReversed?: boolean;
    inverseCoset?: boolean;
  }): Promise<Uint8Array> {
    const count = ensurePackedElements(options.values, elementBytes, `${label}.pipeline.values`);
    return runPipelinePackedBatch({
      ...options,
      vectorSize: count,
      vectorCount: 1,
    });
  }

  async function computeGroth16QuotientPacked(
    a: Uint8Array,
    b: Uint8Array,
    c: Uint8Array,
    inputMontgomery: boolean,
  ): Promise<Uint8Array> {
    const count = ensurePackedElements(a, elementBytes, `${label}.groth16.a`);
    if (b.byteLength !== a.byteLength || c.byteLength !== a.byteLength) {
      throw new Error(`${label}: Groth16 quotient inputs must have identical packed lengths`);
    }
    if (count === 0 || (count & (count - 1)) !== 0) {
      throw new Error(`${label}: Groth16 quotient input length must be a non-zero power of two`);
    }

    const domain = await prepareDomain(count);
    const [aMont, bMont, cMont] = inputMontgomery
      ? [a, b, c]
      : await Promise.all([
          fr.toMontgomeryPacked(a),
          fr.toMontgomeryPacked(b),
          fr.toMontgomeryPacked(c),
        ]);
    const [aCoeffMont, bCoeffMont, cCoeffMont] = await Promise.all([
      runPipelinePacked({ values: aMont, inverse: true, inputRegular: false, outputRegular: false }),
      runPipelinePacked({ values: bMont, inverse: true, inputRegular: false, outputRegular: false }),
      runPipelinePacked({ values: cMont, inverse: true, inputRegular: false, outputRegular: false }),
    ]);
    const [aCosetInputMont, bCosetInputMont, cCosetInputMont] = await Promise.all([
      runVectorOpPacked(VECTOR_OP_MUL_FACTORS, aCoeffMont, domain.cosetPowersPackedMont),
      runVectorOpPacked(VECTOR_OP_MUL_FACTORS, bCoeffMont, domain.cosetPowersPackedMont),
      runVectorOpPacked(VECTOR_OP_MUL_FACTORS, cCoeffMont, domain.cosetPowersPackedMont),
    ]);
    const [aCosetMont, bCosetMont, cCosetMont] = await Promise.all([
      runPipelinePacked({ values: aCosetInputMont, inverse: false, inputRegular: false, outputRegular: false }),
      runPipelinePacked({ values: bCosetInputMont, inverse: false, inputRegular: false, outputRegular: false }),
      runPipelinePacked({ values: cCosetInputMont, inverse: false, inputRegular: false, outputRegular: false }),
    ]);
    const abCosetMont = await runFieldOpPacked(FIELD_OP_MUL, aCosetMont, bCosetMont);
    const numeratorCosetMont = await runFieldOpPacked(FIELD_OP_SUB, abCosetMont, cCosetMont);
    const scaledCosetMont = await runVectorOpPacked(
      VECTOR_OP_MUL_FACTORS,
      numeratorCosetMont,
      domain.cosetDenInvFactorsPackedMont,
    );
    const hShiftedCoeffMont = await runPipelinePacked({
      values: scaledCosetMont,
      inverse: true,
      inputRegular: false,
      outputRegular: false,
    });
    const hCoeffMont = await runVectorOpPacked(
      VECTOR_OP_MUL_FACTORS,
      hShiftedCoeffMont,
      domain.inverseCosetPowersPackedMont,
    );
    const hCoeffRegular = await fr.fromMontgomeryPacked(hCoeffMont);
    return runVectorOpPacked(VECTOR_OP_BIT_REVERSE_COPY, hCoeffRegular, undefined, Math.round(Math.log2(count)));
  }

  async function prewarmGroth16QuotientDomain(size: number): Promise<void> {
    await prepareDomain(size);
  }

  return {
    context,
    curve,
    field: "fr",
    async supportedSizes(): Promise<number[]> {
      const file = await getDomains();
      return file.domains.map((domain) => domain.size).sort((a, b) => a - b);
    },
    async forward(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      values.forEach((value, index) => ensureByteLength(value, elementBytes, `${label}.forward[${index}]`));
      const size = values.length;
      if (size === 0 || (size & (size - 1)) !== 0) {
        throw new Error(`${label}: NTT input length must be a non-zero power of two`);
      }
      const output = await runPipelinePacked({
        values: packElementBatch(values, elementBytes, `${label}.forward.values`),
        inverse: false,
        inputRegular: false,
        outputRegular: false,
      });
      return unpackElementBatch(output, elementBytes, size);
    },
    async inverse(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      values.forEach((value, index) => ensureByteLength(value, elementBytes, `${label}.inverse[${index}]`));
      const size = values.length;
      if (size === 0 || (size & (size - 1)) !== 0) {
        throw new Error(`${label}: NTT input length must be a non-zero power of two`);
      }
      const output = await runPipelinePacked({
        values: packElementBatch(values, elementBytes, `${label}.inverse.values`),
        inverse: true,
        inputRegular: false,
        outputRegular: false,
      });
      return unpackElementBatch(output, elementBytes, size);
    },
    async forwardPackedMont(values: Uint8Array): Promise<Uint8Array> {
      return runPipelinePacked({ values, inverse: false, inputRegular: false, outputRegular: false });
    },
    async inversePackedMont(values: Uint8Array): Promise<Uint8Array> {
      return runPipelinePacked({ values, inverse: true, inputRegular: false, outputRegular: false });
    },
    async forwardPackedMontBatch(values: Uint8Array, vectorSize: number, vectorCount: number): Promise<Uint8Array> {
      return runPipelinePackedBatch({ values, vectorSize, vectorCount, inverse: false, inputRegular: false, outputRegular: false });
    },
    async inversePackedMontBatch(values: Uint8Array, vectorSize: number, vectorCount: number): Promise<Uint8Array> {
      return runPipelinePackedBatch({ values, vectorSize, vectorCount, inverse: true, inputRegular: false, outputRegular: false });
    },
    async inverseBitReversePackedRegular(values: Uint8Array): Promise<Uint8Array> {
      return runPipelinePacked({
        values,
        inverse: true,
        inputRegular: true,
        outputRegular: true,
        inputBitReversed: true,
      });
    },
    async inverseCosetPackedRegular(values: Uint8Array): Promise<Uint8Array> {
      return runPipelinePacked({
        values,
        inverse: true,
        inputRegular: true,
        outputRegular: true,
        inverseCoset: true,
      });
    },
    async inverseCosetBitReversePackedRegular(values: Uint8Array): Promise<Uint8Array> {
      return runPipelinePacked({
        values,
        inverse: true,
        inputRegular: true,
        outputRegular: true,
        inputBitReversed: true,
        inverseCoset: true,
      });
    },
    async forwardPackedRegular(values: Uint8Array): Promise<Uint8Array> {
      return runPipelinePacked({ values, inverse: false, inputRegular: true, outputRegular: true });
    },
    async inversePackedRegular(values: Uint8Array): Promise<Uint8Array> {
      return runPipelinePacked({ values, inverse: true, inputRegular: true, outputRegular: true });
    },
    prewarmDomain: prewarmGroth16QuotientDomain,
    prewarmGroth16QuotientDomain,
    async computeGroth16QuotientPackedRegular(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array> {
      return computeGroth16QuotientPacked(a, b, c, false);
    },
    async computeGroth16QuotientPackedMont(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array> {
      return computeGroth16QuotientPacked(a, b, c, true);
    },
  };
}
