export { };

import { bytesToHex, fetchJSON, hexToBytes } from "../../../src/curvegpu/browser_utils.js";
import type {
  CurveGPUElementBytes,
  CurveGPUFp2Element,
  CurveGPUG2AffinePoint,
  CurveGPUG2JacobianPoint,
  CurveModule,
  SupportedCurveID,
} from "../../../src/index.js";
import { curveDisplayName } from "./shared/page_library.js";

type Fp2Point = {
  c0_bytes_le: string;
  c1_bytes_le: string;
};

type AffinePoint = {
  x: Fp2Point;
  y: Fp2Point;
};

type JacobianPoint = {
  x: Fp2Point;
  y: Fp2Point;
  z: Fp2Point;
};

type MSMCase = {
  name: string;
  bases_affine: AffinePoint[];
  scalars_bytes_le: string[];
  expected_affine: JacobianPoint;
};

type G2MSMVectors = {
  terms_per_instance: number;
  msm_cases: MSMCase[];
};

type G2MSMConfig = {
  curve: SupportedCurveID;
  title: string;
  vectorPath: string;
};

const CONFIGS: Partial<Record<SupportedCurveID, G2MSMConfig>> = {
  bn254: {
    curve: "bn254",
    title: "BN254 G2 MSM Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g2/bn254_g2_msm.json",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 G2 MSM Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g2/bls12_377_g2_msm.json",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 G2 MSM Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g2/bls12_381_g2_msm.json",
  },
};

function fp2FromHex(point: Fp2Point): CurveGPUFp2Element {
  return { c0: hexToBytes(point.c0_bytes_le), c1: hexToBytes(point.c1_bytes_le) };
}

function affineFromHex(point: AffinePoint): CurveGPUG2AffinePoint {
  return { x: fp2FromHex(point.x), y: fp2FromHex(point.y) };
}

function affineToHex(point: CurveGPUG2AffinePoint): AffinePoint {
  return {
    x: { c0_bytes_le: bytesToHex(point.x.c0), c1_bytes_le: bytesToHex(point.x.c1) },
    y: { c0_bytes_le: bytesToHex(point.y.c0), c1_bytes_le: bytesToHex(point.y.c1) },
  };
}

function toAffinePoint(point: CurveGPUG2JacobianPoint): CurveGPUG2AffinePoint {
  return { x: point.x, y: point.y };
}

function equalFp2(a: Fp2Point, b: Fp2Point): boolean {
  return a.c0_bytes_le === b.c0_bytes_le && a.c1_bytes_le === b.c1_bytes_le;
}

function expectAffineBatch(name: string, got: readonly CurveGPUG2AffinePoint[], want: readonly JacobianPoint[]): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = affineToHex(got[i]);
    if (!equalFp2(gotHex.x, want[i].x) || !equalFp2(gotHex.y, want[i].y)) {
      throw new Error(
        `${name}: mismatch at index ${i}` +
        ` got=(${gotHex.x.c0_bytes_le}/${gotHex.x.c1_bytes_le},${gotHex.y.c0_bytes_le}/${gotHex.y.c1_bytes_le})` +
        ` want=(${want[i].x.c0_bytes_le}/${want[i].x.c1_bytes_le},${want[i].y.c0_bytes_le}/${want[i].y.c1_bytes_le})`,
      );
    }
  }
}

async function expectJacobianBatchAffineEqual(
  module: CurveModule,
  name: string,
  got: readonly CurveGPUG2JacobianPoint[],
  want: readonly JacobianPoint[],
): Promise<void> {
  const affine = await module.g2.jacobianToAffineBatch(got);
  expectAffineBatch(name, affine, want);
}

function packAffinePointsWithOneZ(
  bases: readonly CurveGPUG2AffinePoint[],
  componentBytes: number,
  pointBytes: number,
  oneMontC0: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(bases.length * pointBytes);
  for (let i = 0; i < bases.length; i += 1) {
    const base = i * pointBytes;
    out.set(bases[i].x.c0, base);
    out.set(bases[i].x.c1, base + componentBytes);
    out.set(bases[i].y.c0, base + 2 * componentBytes);
    out.set(bases[i].y.c1, base + 3 * componentBytes);
    const isInfinity =
      bases[i].x.c0.every((byte) => byte === 0) &&
      bases[i].x.c1.every((byte) => byte === 0) &&
      bases[i].y.c0.every((byte) => byte === 0) &&
      bases[i].y.c1.every((byte) => byte === 0);
    if (!isInfinity) {
      out.set(oneMontC0, base + 4 * componentBytes);
    }
  }
  return out;
}

function packScalars(scalars: readonly CurveGPUElementBytes[]): Uint8Array {
  const out = new Uint8Array(scalars.length * 32);
  for (let i = 0; i < scalars.length; i += 1) {
    out.set(scalars[i], i * 32);
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
        c0: bytes.slice(base, base + componentBytes),
        c1: bytes.slice(base + componentBytes, base + 2 * componentBytes),
      },
      y: {
        c0: bytes.slice(base + 2 * componentBytes, base + 3 * componentBytes),
        c1: bytes.slice(base + 3 * componentBytes, base + 4 * componentBytes),
      },
      z: {
        c0: bytes.slice(base + 4 * componentBytes, base + 5 * componentBytes),
        c1: bytes.slice(base + 5 * componentBytes, base + 6 * componentBytes),
      },
    });
  }
  return out;
}

async function naiveMSMAffine(
  module: CurveModule,
  bases: readonly CurveGPUG2AffinePoint[],
  scalars: readonly CurveGPUElementBytes[],
): Promise<CurveGPUG2AffinePoint> {
  const scaled = await module.g2.scalarMulAffineBatch(bases, scalars);
  if (scaled.length === 0) {
    return module.g2.affineInfinity();
  }
  let accJacobian = await module.g2.affineToJacobian(toAffinePoint(scaled[0]));
  for (let i = 1; i < scaled.length; i += 1) {
    accJacobian = await module.g2.addMixed(accJacobian, toAffinePoint(scaled[i]));
  }
  return module.g2.jacobianToAffine(accJacobian);
}

export async function runSuite(module: CurveModule, log: (msg: string) => void): Promise<{ passed: number; failed: number }> {
  const config = CONFIGS[module.id];
  if (!config) {
    throw new Error(`g2 MSM vectors unavailable for curve ${module.id}`);
  }
  log(`=== ${config.title} ===`);
  log("");
  const vectors = await fetchJSON<G2MSMVectors>(config.vectorPath);
  log(`terms_per_instance = ${vectors.terms_per_instance}`);
  log(`cases.msm = ${vectors.msm_cases.length}`);

  const naiveResults: CurveGPUG2AffinePoint[] = [];
  for (const msmCase of vectors.msm_cases) {
    naiveResults.push(
      await naiveMSMAffine(
        module,
        msmCase.bases_affine.map(affineFromHex),
        msmCase.scalars_bytes_le.map((value) => hexToBytes(value) as CurveGPUElementBytes),
      ),
    );
  }
  expectAffineBatch("msm_naive_affine", naiveResults, vectors.msm_cases.map((item) => item.expected_affine));
  log("msm_naive_affine: OK");

  const window = 4;
  const pippengerResults = await module.g2msm.pippengerAffineBatch(
    vectors.msm_cases.flatMap((item) => item.bases_affine.map(affineFromHex)),
    vectors.msm_cases.flatMap((item) => item.scalars_bytes_le.map((value) => hexToBytes(value) as CurveGPUElementBytes)),
    {
      count: vectors.msm_cases.length,
      termsPerInstance: vectors.terms_per_instance,
      window,
    },
  );
  await expectJacobianBatchAffineEqual(module, `msm_jac_pippenger_affine_input (window=${window})`, pippengerResults, vectors.msm_cases.map((item) => item.expected_affine));
  log(`msm_jac_pippenger_affine_input (window=${window}): OK`);

  const oneMontC0 = await module.fp.montOne();
  const packedBases = packAffinePointsWithOneZ(
    vectors.msm_cases.flatMap((item) => item.bases_affine.map(affineFromHex)),
    module.g2.componentBytes,
    module.g2.pointBytes,
    oneMontC0,
  );
  const packedScalars = packScalars(
    vectors.msm_cases.flatMap((item) => item.scalars_bytes_le.map((value) => hexToBytes(value) as CurveGPUElementBytes)),
  );

  const jacPackedResults = unpackJacobianPoints(
    await module.g2msm.pippengerPackedJacobianBases(packedBases, packedScalars, {
      count: vectors.msm_cases.length,
      termsPerInstance: vectors.terms_per_instance,
      window,
    }),
    vectors.msm_cases.length,
    module.g2.componentBytes,
    module.g2.pointBytes,
  );
  await expectJacobianBatchAffineEqual(module, `msm_jac_pippenger_packed (window=${window})`, jacPackedResults, vectors.msm_cases.map((item) => item.expected_affine));
  log(`msm_jac_pippenger_packed (window=${window}): OK`);

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G2 MSM browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
