import type {
  CurveGPUContext,
  G1Module,
  G1MSMModule,
  G2Module,
  G2MSMModule,
  Groth16QuotientModule,
  SupportedCurveID,
} from "./api.js";

const CURVE_CONFIG: Record<SupportedCurveID, {
  g1CoordinateBytes: number;
  g1PointBytes: number;
  g2ComponentBytes: number;
  g2PointBytes: number;
}> = {
  bn254: {
    g1CoordinateBytes: 32,
    g1PointBytes: 96,
    g2ComponentBytes: 32,
    g2PointBytes: 192,
  },
  bls12_381: {
    g1CoordinateBytes: 48,
    g1PointBytes: 144,
    g2ComponentBytes: 48,
    g2PointBytes: 288,
  },
  bls12_377: {
    g1CoordinateBytes: 48,
    g1PointBytes: 144,
    g2ComponentBytes: 48,
    g2PointBytes: 288,
  },
};

type BridgeDependencies = {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  g1: G1Module;
  g2: G2Module;
  g1msm: G1MSMModule;
  g2msm: G2MSMModule;
  quotient: Groth16QuotientModule;
};

type CachedKey = {
  curve: SupportedCurveID;
  g1A: Uint8Array;
  g1ACount: number;
  g1B: Uint8Array;
  g1BCount: number;
  g1K: Uint8Array;
  g1KCount: number;
  g1Z: Uint8Array;
  g1ZCount: number;
  g2B: Uint8Array;
  g2BCount: number;
  commitmentCount: number;
  [name: string]: SupportedCurveID | Uint8Array | number;
};

let activeBridge: BridgeDependencies | null = null;
let nextHandle = 1;
const keyCache = new Map<string, CachedKey>();

function cloneBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function assertBridge(curve: string): BridgeDependencies {
  if (!activeBridge) {
    throw new Error("Groth16 WebGPU bridge is not initialized");
  }
  if (curve !== activeBridge.curve) {
    throw new Error(`Groth16 WebGPU bridge is bound to ${activeBridge.curve}, got ${curve}`);
  }
  return activeBridge;
}

function unpackG1JacobianPoint(curve: SupportedCurveID, packedPoint: Uint8Array) {
  const coordinateBytes = CURVE_CONFIG[curve].g1CoordinateBytes;
  return {
    x: cloneBytes(packedPoint.slice(0, coordinateBytes)),
    y: cloneBytes(packedPoint.slice(coordinateBytes, 2 * coordinateBytes)),
    z: cloneBytes(packedPoint.slice(2 * coordinateBytes, 3 * coordinateBytes)),
  };
}

function unpackG2JacobianPoint(curve: SupportedCurveID, packedPoint: Uint8Array) {
  const componentBytes = CURVE_CONFIG[curve].g2ComponentBytes;
  return {
    x: {
      c0: cloneBytes(packedPoint.slice(0, componentBytes)),
      c1: cloneBytes(packedPoint.slice(componentBytes, 2 * componentBytes)),
    },
    y: {
      c0: cloneBytes(packedPoint.slice(2 * componentBytes, 3 * componentBytes)),
      c1: cloneBytes(packedPoint.slice(3 * componentBytes, 4 * componentBytes)),
    },
    z: {
      c0: cloneBytes(packedPoint.slice(4 * componentBytes, 5 * componentBytes)),
      c1: cloneBytes(packedPoint.slice(5 * componentBytes, 6 * componentBytes)),
    },
  };
}

function getKey(handle: string): CachedKey {
  const entry = keyCache.get(handle);
  if (!entry) {
    throw new Error(`unknown Groth16 key handle ${handle}`);
  }
  return entry;
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
  const handle = `${curve}:${nextHandle++}`;
  const commitmentCount = Number(payload.commitmentCount ?? 0);
  const entry: CachedKey = {
    curve,
    g1A: cloneBytes(payload.g1A as Uint8Array),
    g1ACount: Number(payload.g1ACount),
    g1B: cloneBytes(payload.g1B as Uint8Array),
    g1BCount: Number(payload.g1BCount),
    g1K: cloneBytes(payload.g1K as Uint8Array),
    g1KCount: Number(payload.g1KCount),
    g1Z: cloneBytes(payload.g1Z as Uint8Array),
    g1ZCount: Number(payload.g1ZCount),
    g2B: cloneBytes(payload.g2B as Uint8Array),
    g2BCount: Number(payload.g2BCount),
    commitmentCount,
  };
  for (let i = 0; i < commitmentCount; i++) {
    const basisName = `commitmentBasis${i}`;
    const basisExpSigmaName = `commitmentBasisExpSigma${i}`;
    entry[basisName] = cloneBytes(payload[basisName] as Uint8Array);
    entry[`${basisName}Count`] = Number(payload[`${basisName}Count`]);
    entry[basisExpSigmaName] = cloneBytes(payload[basisExpSigmaName] as Uint8Array);
    entry[`${basisExpSigmaName}Count`] = Number(payload[`${basisExpSigmaName}Count`]);
  }
  keyCache.set(handle, entry);
  return { handle };
}

async function msmG1Cached(entry: CachedKey, vectorName: string, scalarsPacked: Uint8Array): Promise<Uint8Array> {
  const bridge = assertBridge(entry.curve);
  const config = CURVE_CONFIG[entry.curve];
  const basesPacked = entry[vectorName];
  const count = entry[`${vectorName}Count`];
  if (!(basesPacked instanceof Uint8Array) || typeof count !== "number") {
    throw new Error(`missing cached G1 vector ${vectorName}`);
  }
  const resultPacked = await bridge.g1msm.pippengerPackedJacobianBases(basesPacked, scalarsPacked, {
    count: 1,
    termsPerInstance: count,
    window: bridge.g1msm.bestWindow(count),
  });
  const jacobian = unpackG1JacobianPoint(entry.curve, resultPacked.slice(0, config.g1PointBytes));
  const affine = await bridge.g1.jacobianToAffine(jacobian);
  const out = new Uint8Array(2 * config.g1CoordinateBytes);
  out.set(affine.x, 0);
  out.set(affine.y, config.g1CoordinateBytes);
  return out;
}

async function msmG2Cached(entry: CachedKey, vectorName: string, scalarsPacked: Uint8Array): Promise<Uint8Array> {
  const bridge = assertBridge(entry.curve);
  const config = CURVE_CONFIG[entry.curve];
  const basesPacked = entry[vectorName];
  const count = entry[`${vectorName}Count`];
  if (!(basesPacked instanceof Uint8Array) || typeof count !== "number") {
    throw new Error(`missing cached G2 vector ${vectorName}`);
  }
  const resultPacked = await bridge.g2msm.pippengerPackedJacobianBases(basesPacked, cloneBytes(scalarsPacked), {
    count: 1,
    termsPerInstance: count,
    window: bridge.g2msm.bestWindow(count),
  });
  const jacobian = unpackG2JacobianPoint(entry.curve, resultPacked.slice(0, config.g2PointBytes));
  const affine = await bridge.g2.jacobianToAffine(jacobian);
  const out = new Uint8Array(4 * config.g2ComponentBytes);
  out.set(affine.x.c0, 0);
  out.set(affine.x.c1, config.g2ComponentBytes);
  out.set(affine.y.c0, 2 * config.g2ComponentBytes);
  out.set(affine.y.c1, 3 * config.g2ComponentBytes);
  return out;
}

async function msmG1(handle: string, vectorName: string, scalarsPacked: Uint8Array) {
  return msmG1Cached(getKey(handle), vectorName, cloneBytes(scalarsPacked));
}

async function msmBatch(handle: string, payload: Record<string, Uint8Array | undefined>) {
  const entry = getKey(handle);
  const points: Record<string, Uint8Array> = {};

  if (payload.g1A) {
    points.g1A = await msmG1Cached(entry, "g1A", payload.g1A);
  }
  if (payload.g1B) {
    points.g1B = await msmG1Cached(entry, "g1B", payload.g1B);
    points.g2B = await msmG2Cached(entry, "g2B", payload.g1B);
  }
  if (payload.g1K) {
    points.g1K = await msmG1Cached(entry, "g1K", payload.g1K);
  }

  return points;
}

async function computeHZMSMG1(handle: string, aPacked: Uint8Array, bPacked: Uint8Array, cPacked: Uint8Array) {
  const entry = getKey(handle);
  const bridge = assertBridge(entry.curve);
  const quotient = await bridge.quotient.computeGroth16QuotientPackedMont(
    cloneBytes(aPacked),
    cloneBytes(bPacked),
    cloneBytes(cPacked),
  );
  const zCount = Number(entry.g1ZCount);
  const scalars = quotient.subarray(0, zCount * 32);
  return msmG1Cached(entry, "g1Z", scalars);
}

async function prewarmQuotientDomain(curve: SupportedCurveID, size: number) {
  const bridge = assertBridge(curve);
  await bridge.quotient.prewarmGroth16QuotientDomain(Number(size));
}

export function installGroth16WebGPUBridge(dependencies: BridgeDependencies): void {
  activeBridge = dependencies;
  (globalThis as typeof globalThis & { gnarkGroth16WebGPU?: unknown }).gnarkGroth16WebGPU = {
    init,
    prepareKey,
    msmG1,
    msmBatch,
    computeHZMSMG1,
    prewarmQuotientDomain,
  };
}
