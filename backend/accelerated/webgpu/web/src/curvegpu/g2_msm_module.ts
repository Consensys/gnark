import type {
  CurveGPUContext,
  CurveGPUElementBytes,
  CurveGPUG2AffinePoint,
  CurveGPUG2JacobianPoint,
  CurveGPUMSMOptions,
  FieldModule,
  G2Module,
  G2MSMModule,
  SupportedCurveID,
} from "./api.js";
import { splitBytesLEToU32 } from "./convert.js";
import { bestPippengerWindow } from "./msm_shared.js";
import { runSparseSignedPippengerMSM, type PippengerRuntime } from "./msm_pippenger.js";
import { lazyAsync } from "./runtime_common.js";

function packScalarWords(scalars: readonly Uint8Array[]): Uint32Array {
  const out = new Uint32Array(scalars.length * 8);
  scalars.forEach((scalar, index) => {
    out.set(splitBytesLEToU32(scalar), index * 8);
  });
  return out;
}

function packScalarWordsPacked(scalarsPacked: Uint8Array): Uint32Array {
  if (scalarsPacked.byteLength % 32 !== 0) {
    throw new Error(`packed scalars: expected a multiple of 32 bytes, got ${scalarsPacked.byteLength}`);
  }
  const count = scalarsPacked.byteLength / 32;
  const out = new Uint32Array(count * 8);
  const view = new DataView(scalarsPacked.buffer, scalarsPacked.byteOffset, scalarsPacked.byteLength);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = view.getUint32(i * 4, true);
  }
  return out;
}

function ensurePackedScalars(scalarsPacked: Uint8Array, count: number, label: string): void {
  const expected = count * 32;
  if (scalarsPacked.byteLength !== expected) {
    throw new Error(`${label}: expected ${expected} scalar bytes, got ${scalarsPacked.byteLength}`);
  }
}

function packAffinesToJacobianPacked(
  bases: readonly CurveGPUG2AffinePoint[],
  componentBytes: number,
  pointBytes: number,
  montOne: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(bases.length * pointBytes);
  for (let i = 0; i < bases.length; i += 1) {
    const base = i * pointBytes;
    const b = bases[i];
    const isInfinity =
      b.x.c0.every((byte) => byte === 0) &&
      b.x.c1.every((byte) => byte === 0) &&
      b.y.c0.every((byte) => byte === 0) &&
      b.y.c1.every((byte) => byte === 0);
    if (!isInfinity) {
      out.set(b.x.c0, base);
      out.set(b.x.c1, base + componentBytes);
      out.set(b.y.c0, base + 2 * componentBytes);
      out.set(b.y.c1, base + 3 * componentBytes);
      // z = fp2_one: c0 = mont_one, c1 = zero
      out.set(montOne, base + 4 * componentBytes);
      // c1 of z remains zero (already zero from new Uint8Array)
    }
    // infinity: all zeros already
  }
  return out;
}

function unpackJacobianPoints(
  bytes: Uint8Array,
  count: number,
  componentBytes: number,
  pointBytes: number,
): CurveGPUG2JacobianPoint[] {
  const out: CurveGPUG2JacobianPoint[] = [];
  for (let i = 0; i < count; i += 1) {
    const base = i * pointBytes;
    out.push({
      x: {
        c0: new Uint8Array(bytes.slice(base, base + componentBytes)),
        c1: new Uint8Array(bytes.slice(base + componentBytes, base + 2 * componentBytes)),
      },
      y: {
        c0: new Uint8Array(bytes.slice(base + 2 * componentBytes, base + 3 * componentBytes)),
        c1: new Uint8Array(bytes.slice(base + 3 * componentBytes, base + 4 * componentBytes)),
      },
      z: {
        c0: new Uint8Array(bytes.slice(base + 4 * componentBytes, base + 5 * componentBytes)),
        c1: new Uint8Array(bytes.slice(base + 5 * componentBytes, base + 6 * componentBytes)),
      },
    });
  }
  return out;
}

export function createG2MSMModule(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    componentBytes: number;
    pointBytes: number;
    runtime: PippengerRuntime;
  },
  g2: G2Module,
  fp: FieldModule,
): G2MSMModule {
  const { curve, componentBytes, pointBytes, runtime } = options;
  const label = `${curve}-g2-msm`;

  const getOneMontgomery = lazyAsync(async () => fp.montOne());

  async function runBatch(
    bases: readonly CurveGPUG2AffinePoint[],
    scalars: readonly CurveGPUElementBytes[],
    msmOptions: CurveGPUMSMOptions = {},
  ): Promise<CurveGPUG2JacobianPoint[]> {
    if (bases.length !== scalars.length) {
      throw new Error(`${label}: bases and scalars length mismatch`);
    }
    const count = msmOptions.count ?? 1;
    const termsPerInstance = msmOptions.termsPerInstance ?? (count === 1 ? bases.length : 0);
    if (!Number.isInteger(count) || count <= 0) {
      throw new Error(`${label}: count must be a positive integer`);
    }
    if (!Number.isInteger(termsPerInstance) || termsPerInstance <= 0) {
      throw new Error(`${label}: termsPerInstance must be a positive integer`);
    }
    if (bases.length !== count * termsPerInstance) {
      throw new Error(`${label}: expected ${count * termsPerInstance} bases/scalars for count=${count} termsPerInstance=${termsPerInstance}`);
    }

    const montOne = await getOneMontgomery();
    const window = msmOptions.window ?? bestPippengerWindow(termsPerInstance);
    const basesBytes = packAffinesToJacobianPacked(bases, componentBytes, pointBytes, montOne);
    const scalarWords = packScalarWords(scalars as Uint8Array[]);
    const outputBytes = await runSparseSignedPippengerMSM({
      device: context.device,
      pool: context.bufferPool,
      runtime,
      basesBytes,
      pointBytes,
      uniformBytes: 32,
      zeroPointBytes: new Uint8Array(pointBytes),
      scalarWords,
      count,
      termsPerInstance,
      window,
      maxChunkSize: msmOptions.maxChunkSize,
      labelPrefix: label,
      debug: context.debug,
    });
    return unpackJacobianPoints(outputBytes, count, componentBytes, pointBytes);
  }

  return {
    context,
    curve,
    group: "g2",
    bestWindow(termCount: number): number {
      return bestPippengerWindow(termCount);
    },
    async pippengerAffine(
      bases: readonly CurveGPUG2AffinePoint[],
      scalars: readonly CurveGPUElementBytes[],
      msmOptions: CurveGPUMSMOptions = {},
    ): Promise<CurveGPUG2JacobianPoint> {
      return (await runBatch(bases, scalars, { ...msmOptions, count: msmOptions.count ?? 1 }))[0];
    },
    async pippengerAffineResult(
      bases: readonly CurveGPUG2AffinePoint[],
      scalars: readonly CurveGPUElementBytes[],
      msmOptions: CurveGPUMSMOptions = {},
    ): Promise<CurveGPUG2AffinePoint> {
      return g2.jacobianToAffine(await this.pippengerAffine(bases, scalars, msmOptions));
    },
    async pippengerAffineBatch(
      bases: readonly CurveGPUG2AffinePoint[],
      scalars: readonly CurveGPUElementBytes[],
      msmOptions: CurveGPUMSMOptions,
    ): Promise<CurveGPUG2JacobianPoint[]> {
      return runBatch(bases, scalars, msmOptions);
    },
    async pippengerPackedJacobianBases(
      basesPacked: Uint8Array,
      scalarsPacked: Uint8Array,
      msmOptions: CurveGPUMSMOptions,
    ): Promise<Uint8Array> {
      const count = msmOptions.count ?? 1;
      const termsPerInstance = msmOptions.termsPerInstance ?? 0;
      if (!Number.isInteger(count) || count <= 0) {
        throw new Error(`${label}: count must be a positive integer`);
      }
      if (!Number.isInteger(termsPerInstance) || termsPerInstance <= 0) {
        throw new Error(`${label}: termsPerInstance must be a positive integer`);
      }
      const expectedPointBytes = count * termsPerInstance * pointBytes;
      if (basesPacked.byteLength !== expectedPointBytes) {
        throw new Error(`${label}: expected ${expectedPointBytes} base bytes, got ${basesPacked.byteLength}`);
      }
      ensurePackedScalars(scalarsPacked, count * termsPerInstance, `${label}.scalarsPacked`);
      const window = msmOptions.window ?? bestPippengerWindow(termsPerInstance);
      return runSparseSignedPippengerMSM({
        device: context.device,
        pool: context.bufferPool,
        runtime,
        basesBytes: basesPacked,
        pointBytes,
        uniformBytes: 32,
        zeroPointBytes: new Uint8Array(pointBytes),
        scalarWords: packScalarWordsPacked(scalarsPacked),
        count,
        termsPerInstance,
        window,
        maxChunkSize: msmOptions.maxChunkSize,
        labelPrefix: label,
        debug: context.debug,
      });
    },
  };
}
