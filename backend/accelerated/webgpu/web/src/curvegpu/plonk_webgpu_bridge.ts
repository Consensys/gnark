import type { CurveGPUContext, FieldModule, G1Module, G1MSMModule, NTTModule, SupportedCurveID } from "./api.js";
import type { PlonkQuotientModule } from "./plonk_quotient_module.js";

const CURVE_CONFIG: Record<SupportedCurveID, {
  g1CoordinateBytes: number;
  g1PointBytes: number;
}> = {
  bn254: {
    g1CoordinateBytes: 32,
    g1PointBytes: 96,
  },
  bls12_381: {
    g1CoordinateBytes: 48,
    g1PointBytes: 144,
  },
  bls12_377: {
    g1CoordinateBytes: 48,
    g1PointBytes: 144,
  },
};

type BridgeDependencies = {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  fr: FieldModule;
  ntt: NTTModule;
  g1: G1Module;
  g1msm: G1MSMModule;
  quotient: PlonkQuotientModule;
};

type CachedKey = {
  curve: SupportedCurveID;
  kzg: Uint8Array;
  kzgCount: number;
  kzgLagrange: Uint8Array;
  kzgLagrangeCount: number;
};

let activeBridge: BridgeDependencies | null = null;
let nextHandle = 1;
const keyCache = new Map<string, CachedKey>();

function cloneBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function assertBridge(curve: string): BridgeDependencies {
  if (!activeBridge) {
    throw new Error("PLONK WebGPU bridge is not initialized");
  }
  if (curve !== activeBridge.curve) {
    throw new Error(`PLONK WebGPU bridge is bound to ${activeBridge.curve}, got ${curve}`);
  }
  return activeBridge;
}

function getKey(handle: string): CachedKey {
  const entry = keyCache.get(handle);
  if (!entry) {
    throw new Error(`unknown PLONK key handle ${handle}`);
  }
  return entry;
}

function unpackG1JacobianPoint(curve: SupportedCurveID, packedPoint: Uint8Array) {
  const coordinateBytes = CURVE_CONFIG[curve].g1CoordinateBytes;
  return {
    x: cloneBytes(packedPoint.slice(0, coordinateBytes)),
    y: cloneBytes(packedPoint.slice(coordinateBytes, 2 * coordinateBytes)),
    z: cloneBytes(packedPoint.slice(2 * coordinateBytes, 3 * coordinateBytes)),
  };
}

function unpackG1JacobianPoints(curve: SupportedCurveID, packedPoints: Uint8Array, count: number) {
  const pointBytes = CURVE_CONFIG[curve].g1PointBytes;
  if (packedPoints.byteLength !== count * pointBytes) {
    throw new Error(`expected ${count * pointBytes} packed G1 Jacobian bytes, got ${packedPoints.byteLength}`);
  }
  return Array.from({ length: count }, (_, i) => {
    const start = i * pointBytes;
    return unpackG1JacobianPoint(curve, packedPoints.slice(start, start + pointBytes));
  });
}

function packG1AffinePoints(curve: SupportedCurveID, points: readonly { x: Uint8Array; y: Uint8Array }[]) {
  const coordinateBytes = CURVE_CONFIG[curve].g1CoordinateBytes;
  const out = new Uint8Array(points.length * 2 * coordinateBytes);
  for (const [i, point] of points.entries()) {
    const start = i * 2 * coordinateBytes;
    out.set(point.x, start);
    out.set(point.y, start + coordinateBytes);
  }
  return out;
}

async function init(curve: SupportedCurveID) {
  const bridge = assertBridge(curve);
  return {
    curve,
    adapter: {
      vendor: bridge.context.diagnostics.vendor ?? "",
      architecture: bridge.context.diagnostics.architecture ?? "",
      description: bridge.context.diagnostics.description ?? "",
    },
  };
}

async function prepareKey(curve: SupportedCurveID, payload: Record<string, Uint8Array | number | undefined>) {
  assertBridge(curve);
  const kzg = payload.kzg;
  const kzgCount = Number(payload.kzgCount);
  const kzgLagrange = payload.kzgLagrange;
  const kzgLagrangeCount = Number(payload.kzgLagrangeCount);
  if (!(kzg instanceof Uint8Array)) {
    throw new Error("PLONK key payload is missing kzg");
  }
  if (!(kzgLagrange instanceof Uint8Array)) {
    throw new Error("PLONK key payload is missing kzgLagrange");
  }
  if (!Number.isInteger(kzgCount) || kzgCount <= 0) {
    throw new Error(`invalid PLONK kzgCount ${payload.kzgCount}`);
  }
  if (!Number.isInteger(kzgLagrangeCount) || kzgLagrangeCount <= 0) {
    throw new Error(`invalid PLONK kzgLagrangeCount ${payload.kzgLagrangeCount}`);
  }
  const kzgExpectedBytes = kzgCount * CURVE_CONFIG[curve].g1PointBytes;
  if (kzg.byteLength !== kzgExpectedBytes) {
    throw new Error(`PLONK kzg expected ${kzgExpectedBytes} bytes, got ${kzg.byteLength}`);
  }
  const kzgLagrangeExpectedBytes = kzgLagrangeCount * CURVE_CONFIG[curve].g1PointBytes;
  if (kzgLagrange.byteLength !== kzgLagrangeExpectedBytes) {
    throw new Error(`PLONK kzgLagrange expected ${kzgLagrangeExpectedBytes} bytes, got ${kzgLagrange.byteLength}`);
  }
  const handle = `${curve}:${nextHandle++}`;
  const entry: CachedKey = {
    curve,
    kzg: cloneBytes(kzg),
    kzgCount,
    kzgLagrange: cloneBytes(kzgLagrange),
    kzgLagrangeCount,
  };
  keyCache.set(handle, entry);
  return { handle };
}

async function msmG1(handle: string, vectorName: string, scalarsPacked: Uint8Array, start = 0, count?: number) {
  const entry = getKey(handle);
  const bridge = assertBridge(entry.curve);
  const config = CURVE_CONFIG[entry.curve];
  if (vectorName !== "kzg" && vectorName !== "kzgLagrange") {
    throw new Error(`missing cached PLONK G1 vector ${vectorName}`);
  }
  const vector = entry[vectorName];
  const vectorCount = entry[`${vectorName}Count`];
  const termCount = count ?? vectorCount - start;
  if (!Number.isInteger(start) || start < 0 || !Number.isInteger(termCount) || termCount <= 0) {
    throw new Error(`invalid PLONK MSM range start=${start} count=${termCount}`);
  }
  if (start + termCount > vectorCount) {
    throw new Error(`PLONK MSM range exceeds ${vectorName}: start=${start} count=${termCount}`);
  }
  const baseStart = start * config.g1PointBytes;
  const baseEnd = (start + termCount) * config.g1PointBytes;
  const basesPacked = vector.subarray(baseStart, baseEnd);
  const resultPacked = await bridge.g1msm.pippengerPackedJacobianBases(basesPacked, cloneBytes(scalarsPacked), {
    count: 1,
    termsPerInstance: termCount,
    window: bridge.g1msm.bestWindow(termCount),
  });
  const jacobian = unpackG1JacobianPoint(entry.curve, resultPacked.slice(0, config.g1PointBytes));
  const affine = await bridge.g1.jacobianToAffine(jacobian);
  const out = new Uint8Array(2 * config.g1CoordinateBytes);
  out.set(affine.x, 0);
  out.set(affine.y, config.g1CoordinateBytes);
  return out;
}

async function msmG1Batch(
  handle: string,
  vectorName: string,
  scalarsPacked: Uint8Array,
  start = 0,
  termsPerInstance?: number,
  count?: number,
) {
  const entry = getKey(handle);
  const bridge = assertBridge(entry.curve);
  const config = CURVE_CONFIG[entry.curve];
  if (vectorName !== "kzg" && vectorName !== "kzgLagrange") {
    throw new Error(`missing cached PLONK G1 vector ${vectorName}`);
  }
  const vector = entry[vectorName];
  const vectorCount = entry[`${vectorName}Count`];
  const instanceCount = count ?? 0;
  const termCount = termsPerInstance ?? 0;
  if (!Number.isInteger(start) || start < 0 || !Number.isInteger(termCount) || termCount <= 0) {
    throw new Error(`invalid PLONK MSM batch range start=${start} termsPerInstance=${termCount}`);
  }
  if (!Number.isInteger(instanceCount) || instanceCount <= 0) {
    throw new Error(`invalid PLONK MSM batch count ${instanceCount}`);
  }
  if (start + termCount > vectorCount) {
    throw new Error(`PLONK MSM batch range exceeds ${vectorName}: start=${start} termsPerInstance=${termCount}`);
  }

  const scalarBytes = bridge.fr.byteSize * termCount * instanceCount;
  if (scalarsPacked.byteLength !== scalarBytes) {
    throw new Error(`PLONK MSM batch expected ${scalarBytes} scalar bytes, got ${scalarsPacked.byteLength}`);
  }

  const baseStart = start * config.g1PointBytes;
  const baseEnd = (start + termCount) * config.g1PointBytes;
  const bases = vector.subarray(baseStart, baseEnd);
  const basesPacked = new Uint8Array(bases.byteLength * instanceCount);
  for (let i = 0; i < instanceCount; i++) {
    basesPacked.set(bases, i * bases.byteLength);
  }

  const resultPacked = await bridge.g1msm.pippengerPackedJacobianBases(basesPacked, cloneBytes(scalarsPacked), {
    count: instanceCount,
    termsPerInstance: termCount,
    window: bridge.g1msm.bestWindow(termCount),
  });
  const jacobians = unpackG1JacobianPoints(entry.curve, resultPacked, instanceCount);
  const affines = await bridge.g1.jacobianToAffineBatch(jacobians);
  return packG1AffinePoints(entry.curve, affines);
}

async function transformQuotientCoset(
  curve: SupportedCurveID,
  valuesPacked: Uint8Array,
  scalingPacked: Uint8Array,
  vectorCount: number,
  elementCount: number,
) {
  const bridge = assertBridge(curve);
  const elementBytes = bridge.fr.byteSize;
  const vectorBytes = elementCount * elementBytes;
  if (!Number.isInteger(vectorCount) || vectorCount <= 0) {
    throw new Error(`invalid PLONK quotient vector count ${vectorCount}`);
  }
  if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
    throw new Error(`invalid PLONK quotient element count ${elementCount}`);
  }
  if (valuesPacked.byteLength !== vectorCount * vectorBytes) {
    throw new Error(`PLONK quotient transform expected ${vectorCount * vectorBytes} value bytes, got ${valuesPacked.byteLength}`);
  }
  if (scalingPacked.byteLength !== vectorBytes) {
    throw new Error(`PLONK quotient transform expected ${vectorBytes} scaling bytes, got ${scalingPacked.byteLength}`);
  }

  const scalingMont = await bridge.fr.toMontgomeryPacked(cloneBytes(scalingPacked));
  const out = new Uint8Array(valuesPacked.byteLength);
  await Promise.all(
    Array.from({ length: vectorCount }, async (_, i) => {
      const start = i * vectorBytes;
      const end = start + vectorBytes;
      const valuesMont = await bridge.fr.toMontgomeryPacked(cloneBytes(valuesPacked.subarray(start, end)));
      const coeffMont = await bridge.ntt.inversePackedMont(valuesMont);
      const shiftedCoeffMont = await bridge.fr.mulPackedMont(coeffMont, scalingMont);
      const shiftedEvalMont = await bridge.ntt.forwardPackedMont(shiftedCoeffMont);
      const shiftedEvalRegular = await bridge.fr.fromMontgomeryPacked(shiftedEvalMont);
      out.set(shiftedEvalRegular, start);
    }),
  );
  return out;
}

async function canonicalizeQuotientFromCoset(curve: SupportedCurveID, valuesPacked: Uint8Array, elementCount: number) {
  return canonicalizeQuotientVectors(curve, valuesPacked, 1, elementCount, true, true);
}

async function lagrangeQuotientVectors(
  curve: SupportedCurveID,
  valuesPacked: Uint8Array,
  vectorCount: number,
  elementCount: number,
) {
  const bridge = assertBridge(curve);
  const vectorBytes = elementCount * bridge.fr.byteSize;
  if (!Number.isInteger(vectorCount) || vectorCount <= 0) {
    throw new Error(`invalid PLONK quotient lagrange vector count ${vectorCount}`);
  }
  if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
    throw new Error(`invalid PLONK quotient lagrange element count ${elementCount}`);
  }
  if (valuesPacked.byteLength !== vectorCount * vectorBytes) {
    throw new Error(`PLONK quotient lagrange expected ${vectorCount * vectorBytes} value bytes, got ${valuesPacked.byteLength}`);
  }

  const out = new Uint8Array(valuesPacked.byteLength);
  await Promise.all(
    Array.from({ length: vectorCount }, async (_, i) => {
      const start = i * vectorBytes;
      const end = start + vectorBytes;
      const values = cloneBytes(valuesPacked.subarray(start, end));
      out.set(await bridge.ntt.forwardPackedRegular(values), start);
    }),
  );
  return out;
}

async function canonicalizeQuotientVectors(
  curve: SupportedCurveID,
  valuesPacked: Uint8Array,
  vectorCount: number,
  elementCount: number,
  inputBitReversed: boolean,
  inverseCoset: boolean,
) {
  const bridge = assertBridge(curve);
  const vectorBytes = elementCount * bridge.fr.byteSize;
  if (!Number.isInteger(vectorCount) || vectorCount <= 0) {
    throw new Error(`invalid PLONK quotient canonicalize vector count ${vectorCount}`);
  }
  if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
    throw new Error(`invalid PLONK quotient canonicalize element count ${elementCount}`);
  }
  if (valuesPacked.byteLength !== vectorCount * vectorBytes) {
    throw new Error(`PLONK quotient canonicalize expected ${vectorCount * vectorBytes} value bytes, got ${valuesPacked.byteLength}`);
  }

  const out = new Uint8Array(valuesPacked.byteLength);
  await Promise.all(
    Array.from({ length: vectorCount }, async (_, i) => {
      const start = i * vectorBytes;
      const end = start + vectorBytes;
      const input = cloneBytes(valuesPacked.subarray(start, end));
      let canonical: Uint8Array;
      if (inverseCoset) {
        canonical = inputBitReversed
          ? await bridge.ntt.inverseCosetBitReversePackedRegular(input)
          : await bridge.ntt.inverseCosetPackedRegular(input);
      } else {
        canonical = inputBitReversed
          ? await bridge.ntt.inverseBitReversePackedRegular(input)
          : await bridge.ntt.inversePackedRegular(input);
      }
      out.set(canonical, start);
    }),
  );
  return out;
}

async function transformAndEvaluateQuotientCoset(
  curve: SupportedCurveID,
  dynamicValuesPacked: Uint8Array,
  scalingPacked: Uint8Array,
  staticValuesPacked: Uint8Array,
  twiddlesPacked: Uint8Array,
  denominatorsPacked: Uint8Array,
  blindsPacked: Uint8Array,
  scalarsPacked: Uint8Array,
  elementCount: number,
  blindCoeffCount: number,
  commitmentCount: number,
  dynamicTransformCacheKey: number,
  staticMontCacheKey: number,
) {
  const bridge = assertBridge(curve);
  return bridge.quotient.transformAndEvaluateQuotientCoset({
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
    dynamicTransformCacheKey,
    staticMontCacheKey,
  });
}

async function transformAndEvaluateQuotientCosets(
  curve: SupportedCurveID,
  dynamicValuesPacked: Uint8Array,
  scalingPacked: Uint8Array,
  staticValuesPacked: Uint8Array,
  staticMontCacheKeysPacked: Uint8Array,
  twiddlesPacked: Uint8Array,
  denominatorsPacked: Uint8Array,
  blindsPacked: Uint8Array,
  scalarsPacked: Uint8Array,
  elementCount: number,
  blindCoeffCount: number,
  commitmentCount: number,
  dynamicTransformCacheKey: number,
  cosetCount: number,
  auxMontCacheKey: number,
) {
  const bridge = assertBridge(curve);
  return bridge.quotient.transformAndEvaluateQuotientCosets({
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
    dynamicTransformCacheKey,
    cosetCount,
    auxMontCacheKey,
  });
}

async function preloadQuotientStaticAndAux(
  curve: SupportedCurveID,
  staticValuesPacked: Uint8Array,
  staticMontCacheKeysPacked: Uint8Array,
  scalingPacked: Uint8Array,
  twiddlesPacked: Uint8Array,
  denominatorsPacked: Uint8Array,
  elementCount: number,
  staticVectorCount: number,
  cosetCount: number,
  auxMontCacheKey: number,
) {
  const bridge = assertBridge(curve);
  return bridge.quotient.preloadQuotientStaticAndAux({
    staticValuesPacked,
    staticMontCacheKeysPacked,
    scalingPacked,
    twiddlesPacked,
    denominatorsPacked,
    elementCount,
    staticVectorCount,
    cosetCount,
    auxMontCacheKey,
  });
}

async function prewarmQuotientTransformDomain(curve: SupportedCurveID, elementCount: number) {
  const bridge = assertBridge(curve);
  if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
    throw new Error(`invalid PLONK quotient prewarm element count ${elementCount}`);
  }
  await bridge.ntt.prewarmDomain(elementCount);

  // Trigger the exact packed transform path once so first prove does not pay
  // shader/domain lazy initialization in quotient_num_coset_0.
  const zeroVector = new Uint8Array(elementCount * bridge.fr.byteSize);
  await transformQuotientCoset(curve, zeroVector, zeroVector, 1, elementCount);
}

async function prewarmQuotientCanonicalizeDomain(curve: SupportedCurveID, elementCount: number) {
  const bridge = assertBridge(curve);
  if (!Number.isInteger(elementCount) || elementCount <= 0 || (elementCount & (elementCount - 1)) !== 0) {
    throw new Error(`invalid PLONK quotient canonicalize prewarm element count ${elementCount}`);
  }
  await bridge.ntt.prewarmDomain(elementCount);

  const zeroVector = new Uint8Array(elementCount * bridge.fr.byteSize);
  await canonicalizeQuotientFromCoset(curve, zeroVector, elementCount);
}

async function prewarmQuotientEvaluateKernel(curve: SupportedCurveID, commitmentCount = 0) {
  const bridge = assertBridge(curve);
  await bridge.quotient.prewarmPlonkQuotientEvaluateKernel(commitmentCount);
}

export function installPlonkWebGPUBridge(dependencies: BridgeDependencies): void {
  activeBridge = dependencies;
  (globalThis as typeof globalThis & { gnarkPlonkWebGPU?: unknown }).gnarkPlonkWebGPU = {
    init,
    prepareKey,
    msmG1,
    msmG1Batch,
    transformQuotientCoset,
    transformAndEvaluateQuotientCoset,
    transformAndEvaluateQuotientCosets,
    preloadQuotientStaticAndAux,
    canonicalizeQuotientFromCoset,
    lagrangeQuotientVectors,
    canonicalizeQuotientVectors,
    prewarmQuotientTransformDomain,
    prewarmQuotientCanonicalizeDomain,
    prewarmQuotientEvaluateKernel,
  };
}
