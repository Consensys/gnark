export { };

import { bytesToHex, fetchJSON, hexToBytes } from "../../../src/curvegpu/browser_utils.js";
import type {
  CurveGPUAffinePoint,
  CurveGPUJacobianPoint,
  CurveModule,
  G1Module,
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

type G1Case = {
  name: string;
  p_affine: AffinePoint;
  q_affine: AffinePoint;
  p_jacobian: JacobianPoint;
  p_affine_output: JacobianPoint;
  neg_p_jacobian: JacobianPoint;
  double_p_jacobian: JacobianPoint;
  add_mixed_p_plus_q_jacobian: JacobianPoint;
  affine_add_p_plus_q: JacobianPoint;
};

type G1OpsVectors = {
  point_cases: G1Case[];
};

type G1OpsConfig = {
  curve: SupportedCurveID;
  title: string;
  vectorPath: string;
};

const CONFIGS: Partial<Record<SupportedCurveID, G1OpsConfig>> = {
  bn254: {
    curve: "bn254",
    title: "BN254 G1 Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g1/bn254_g1_ops.json",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 G1 Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g1/bls12_377_g1_ops.json",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 G1 Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g1/bls12_381_g1_ops.json",
  },
};

function affineFromHex(point: AffinePoint): CurveGPUAffinePoint {
  return { x: hexToBytes(point.x_bytes_le), y: hexToBytes(point.y_bytes_le) };
}

function jacobianFromHex(point: JacobianPoint): CurveGPUJacobianPoint {
  return {
    x: hexToBytes(point.x_bytes_le),
    y: hexToBytes(point.y_bytes_le),
    z: hexToBytes(point.z_bytes_le),
  };
}

function jacobianToHex(point: CurveGPUJacobianPoint): JacobianPoint {
  return {
    x_bytes_le: bytesToHex(point.x),
    y_bytes_le: bytesToHex(point.y),
    z_bytes_le: bytesToHex(point.z),
  };
}

function affineToHex(point: CurveGPUAffinePoint): AffinePoint {
  return {
    x_bytes_le: bytesToHex(point.x),
    y_bytes_le: bytesToHex(point.y),
  };
}

function expectPointBatch(name: string, got: readonly CurveGPUJacobianPoint[], want: readonly JacobianPoint[], log: (msg: string) => void): void {
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
      throw new Error(`${name}: mismatch at index ${i}`);
    }
  }
  log(`${name}: OK`);
}

function expectAffineBatch(name: string, got: readonly CurveGPUAffinePoint[], want: readonly AffinePoint[], log: (msg: string) => void): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = affineToHex(got[i]);
    if (gotHex.x_bytes_le !== want[i].x_bytes_le || gotHex.y_bytes_le !== want[i].y_bytes_le) {
      throw new Error(`${name}: mismatch at index ${i}`);
    }
  }
  log(`${name}: OK`);
}

export async function runSuite(module: CurveModule, log: (msg: string) => void): Promise<{ passed: number; failed: number }> {
  const config = CONFIGS[module.id];
  if (!config) {
    throw new Error(`g1 ops vectors unavailable for curve ${module.id}`);
  }
  log(`=== ${config.title} ===`);
  log("");
  const vectors = await fetchJSON<G1OpsVectors>(config.vectorPath);
  log(`cases.g1 = ${vectors.point_cases.length}`);

  const g1: G1Module = module.g1;
  const pAffine = vectors.point_cases.map((item) => affineFromHex(item.p_affine));
  const qAffine = vectors.point_cases.map((item) => affineFromHex(item.q_affine));
  const pJacobian = vectors.point_cases.map((item) => jacobianFromHex(item.p_jacobian));
  const negWant = vectors.point_cases.map((item) => item.neg_p_jacobian);
  const doubleWant = vectors.point_cases.map((item) => item.double_p_jacobian);
  const addWant = vectors.point_cases.map((item) => item.add_mixed_p_plus_q_jacobian);
  const affineWant = vectors.point_cases.map((item) => ({
    x_bytes_le: item.p_affine_output.x_bytes_le,
    y_bytes_le: item.p_affine_output.y_bytes_le,
  }));
  const affineAddWant = vectors.point_cases.map((item) => item.affine_add_p_plus_q);
  const oneMont = await module.fp.montOne();
  const jacInfinityWant = vectors.point_cases.map(() => ({
    x_bytes_le: bytesToHex(oneMont),
    y_bytes_le: bytesToHex(oneMont),
    z_bytes_le: bytesToHex(module.fp.zero()),
  }));

  expectPointBatch("copy", await g1.copyBatch(pJacobian), vectors.point_cases.map((item) => item.p_jacobian), log);
  expectPointBatch("jac_infinity", await g1.jacobianInfinityBatch(vectors.point_cases.length), jacInfinityWant, log);
  expectPointBatch("affine_to_jac", await g1.affineToJacobianBatch(pAffine), vectors.point_cases.map((item) => item.p_jacobian), log);
  expectPointBatch("neg_jac", await g1.negJacobianBatch(pJacobian), negWant, log);
  expectAffineBatch("jac_to_affine", await g1.jacobianToAffineBatch(pJacobian), affineWant, log);
  expectPointBatch("double_jac", await g1.doubleJacobianBatch(pJacobian), doubleWant, log);
  expectPointBatch("add_mixed", await g1.addMixedBatch(pJacobian, qAffine), addWant, log);
  expectPointBatch("affine_add", await g1.affineAddBatch(pAffine, qAffine), affineAddWant, log);

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G1 browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
