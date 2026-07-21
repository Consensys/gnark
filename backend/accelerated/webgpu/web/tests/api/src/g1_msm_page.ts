export { };

import { bytesToHex, fetchJSON, hexToBytes } from "../../../src/curvegpu/browser_utils.js";
import type {
  CurveGPUAffinePoint,
  CurveGPUElementBytes,
  CurveGPUJacobianPoint,
  CurveModule,
  SupportedCurveID,
} from "../../../src/index.js";
import { curveDisplayName } from "./shared/page_library.js";

type AffinePoint = {
  x_bytes_le: string;
  y_bytes_le: string;
};

type JacobianPoint = {
  x_bytes_le: string;
  y_bytes_le: string;
  z_bytes_le: string;
};

type MSMCase = {
  name: string;
  bases_affine: AffinePoint[];
  scalars_bytes_le: string[];
  expected_affine: JacobianPoint;
};

type G1MSMVectors = {
  terms_per_instance: number;
  msm_cases: MSMCase[];
  one_mont_z: string;
};

type G1MSMConfig = {
  curve: SupportedCurveID;
  title: string;
  vectorPath: string;
};

const CONFIGS: Partial<Record<SupportedCurveID, G1MSMConfig>> = {
  bn254: {
    curve: "bn254",
    title: "BN254 G1 MSM Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g1/bn254_g1_msm.json",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 G1 MSM Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g1/bls12_377_g1_msm.json",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 G1 MSM Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g1/bls12_381_g1_msm.json",
  },
};

function affineFromHex(point: AffinePoint): CurveGPUAffinePoint {
  return { x: hexToBytes(point.x_bytes_le), y: hexToBytes(point.y_bytes_le) };
}

function jacobianToHex(point: CurveGPUJacobianPoint): JacobianPoint {
  return {
    x_bytes_le: bytesToHex(point.x),
    y_bytes_le: bytesToHex(point.y),
    z_bytes_le: bytesToHex(point.z),
  };
}

function toAffinePoint(point: CurveGPUJacobianPoint): CurveGPUAffinePoint {
  return { x: point.x, y: point.y };
}

function expectPointBatch(name: string, got: readonly CurveGPUJacobianPoint[], want: readonly JacobianPoint[]): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = jacobianToHex(got[i]);
    if (
      gotHex.x_bytes_le !== want[i].x_bytes_le ||
      gotHex.y_bytes_le !== want[i].y_bytes_le ||
      gotHex.z_bytes_le !== want[i].z_bytes_le
    ) {
      throw new Error(
        `${name}: mismatch at index ${i}` +
        ` got=(${gotHex.x_bytes_le},${gotHex.y_bytes_le},${gotHex.z_bytes_le})` +
        ` want=(${want[i].x_bytes_le},${want[i].y_bytes_le},${want[i].z_bytes_le})`,
      );
    }
  }
}

function expectAffineBatch(name: string, got: readonly CurveGPUAffinePoint[], want: readonly JacobianPoint[]): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = {
      x_bytes_le: bytesToHex(got[i].x),
      y_bytes_le: bytesToHex(got[i].y),
    };
    if (gotHex.x_bytes_le !== want[i].x_bytes_le || gotHex.y_bytes_le !== want[i].y_bytes_le) {
      throw new Error(
        `${name}: mismatch at index ${i}` +
        ` got=(${gotHex.x_bytes_le},${gotHex.y_bytes_le})` +
        ` want=(${want[i].x_bytes_le},${want[i].y_bytes_le})`,
      );
    }
  }
}

async function naiveMSMAffine(
  curve: CurveModule,
  bases: readonly CurveGPUAffinePoint[],
  scalars: readonly CurveGPUElementBytes[],
): Promise<CurveGPUAffinePoint> {
  const scaled = await curve.g1.scalarMulAffineBatch(bases, scalars);
  if (scaled.length === 0) {
    return curve.g1.affineInfinity();
  }
  let accJacobian = await curve.g1.affineToJacobian(toAffinePoint(scaled[0]));
  for (let i = 1; i < scaled.length; i += 1) {
    accJacobian = await curve.g1.addMixed(accJacobian, toAffinePoint(scaled[i]));
  }
  return curve.g1.jacobianToAffine(accJacobian);
}

export async function runSuite(module: CurveModule, log: (msg: string) => void): Promise<{ passed: number; failed: number }> {
  const config = CONFIGS[module.id];
  if (!config) {
    throw new Error(`g1 MSM vectors unavailable for curve ${module.id}`);
  }
  log(`=== ${config.title} ===`);
  log("");
  const vectors = await fetchJSON<G1MSMVectors>(config.vectorPath);
  log(`terms_per_instance = ${vectors.terms_per_instance}`);
  log(`cases.msm = ${vectors.msm_cases.length}`);

  const naiveResults: CurveGPUAffinePoint[] = [];
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
  const pippengerResults = await module.g1msm.pippengerAffineBatch(
    vectors.msm_cases.flatMap((item) => item.bases_affine.map(affineFromHex)),
    vectors.msm_cases.flatMap((item) => item.scalars_bytes_le.map((value) => hexToBytes(value) as CurveGPUElementBytes)),
    {
      count: vectors.msm_cases.length,
      termsPerInstance: vectors.terms_per_instance,
      window,
    },
  );
  expectPointBatch(`msm_jac_pippenger_affine_input (window=${window})`, pippengerResults, vectors.msm_cases.map((item) => item.expected_affine));
  log(`msm_jac_pippenger_affine_input (window=${window}): OK`);

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G1 MSM browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
