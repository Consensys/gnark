export { };

import { bytesToHex, fetchJSON, hexToBytes } from "../../../src/curvegpu/browser_utils.js";
import type {
  CurveGPUFp2Element,
  CurveGPUG2AffinePoint,
  CurveGPUG2JacobianPoint,
  CurveModule,
  G2Module,
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

type G2Case = {
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

type G2OpsVectors = {
  point_cases: G2Case[];
};

type G2OpsConfig = {
  curve: SupportedCurveID;
  title: string;
  vectorPath: string;
};

const CONFIGS: Partial<Record<SupportedCurveID, G2OpsConfig>> = {
  bn254: {
    curve: "bn254",
    title: "BN254 G2 Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g2/bn254_g2_ops.json",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 G2 Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g2/bls12_377_g2_ops.json",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 G2 Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/g2/bls12_381_g2_ops.json",
  },
};

function fp2FromHex(point: Fp2Point): CurveGPUFp2Element {
  return { c0: hexToBytes(point.c0_bytes_le), c1: hexToBytes(point.c1_bytes_le) };
}

function affineFromHex(point: AffinePoint): CurveGPUG2AffinePoint {
  return { x: fp2FromHex(point.x), y: fp2FromHex(point.y) };
}

function jacobianFromHex(point: JacobianPoint): CurveGPUG2JacobianPoint {
  return { x: fp2FromHex(point.x), y: fp2FromHex(point.y), z: fp2FromHex(point.z) };
}

function fp2ToHex(point: CurveGPUFp2Element): Fp2Point {
  return { c0_bytes_le: bytesToHex(point.c0), c1_bytes_le: bytesToHex(point.c1) };
}

function affineToHex(point: CurveGPUG2AffinePoint): AffinePoint {
  return { x: fp2ToHex(point.x), y: fp2ToHex(point.y) };
}

function jacobianToHex(point: CurveGPUG2JacobianPoint): JacobianPoint {
  return { x: fp2ToHex(point.x), y: fp2ToHex(point.y), z: fp2ToHex(point.z) };
}

function equalFp2(a: Fp2Point, b: Fp2Point): boolean {
  return a.c0_bytes_le === b.c0_bytes_le && a.c1_bytes_le === b.c1_bytes_le;
}

function expectPointBatch(name: string, got: readonly CurveGPUG2JacobianPoint[], want: readonly JacobianPoint[], log: (msg: string) => void): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = jacobianToHex(got[i]);
    if (
      !equalFp2(gotHex.x, want[i].x) ||
      !equalFp2(gotHex.y, want[i].y) ||
      !equalFp2(gotHex.z, want[i].z)
    ) {
      throw new Error(`${name}: mismatch at index ${i} got=${JSON.stringify(gotHex)} want=${JSON.stringify(want[i])}`);
    }
  }
  log(`${name}: OK`);
}

function expectAffineBatch(name: string, got: readonly CurveGPUG2AffinePoint[], want: readonly AffinePoint[], log: (msg: string) => void): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = affineToHex(got[i]);
    if (!equalFp2(gotHex.x, want[i].x) || !equalFp2(gotHex.y, want[i].y)) {
      throw new Error(`${name}: mismatch at index ${i} got=${JSON.stringify(gotHex)} want=${JSON.stringify(want[i])}`);
    }
  }
  log(`${name}: OK`);
}

function zeroFp2(componentBytes: number): Fp2Point {
  const zero = bytesToHex(new Uint8Array(componentBytes));
  return { c0_bytes_le: zero, c1_bytes_le: zero };
}

export async function runSuite(module: CurveModule, log: (msg: string) => void): Promise<{ passed: number; failed: number }> {
  const config = CONFIGS[module.id];
  if (!config) {
    throw new Error(`g2 ops vectors unavailable for curve ${module.id}`);
  }
  log(`=== ${config.title} ===`);
  log("");
  const vectors = await fetchJSON<G2OpsVectors>(config.vectorPath);
  log(`cases.g2 = ${vectors.point_cases.length}`);

  const g2: G2Module = module.g2;
  const pAffine = vectors.point_cases.map((item) => affineFromHex(item.p_affine));
  const qAffine = vectors.point_cases.map((item) => affineFromHex(item.q_affine));
  const pJacobian = vectors.point_cases.map((item) => jacobianFromHex(item.p_jacobian));
  const negWant = vectors.point_cases.map((item) => item.neg_p_jacobian);
  const doubleWant = vectors.point_cases.map((item) => item.double_p_jacobian);
  const addWant = vectors.point_cases.map((item) => item.add_mixed_p_plus_q_jacobian);
  const affineWant = vectors.point_cases.map((item) => ({
    x: item.p_affine_output.x,
    y: item.p_affine_output.y,
  }));
  const affineAddWant = vectors.point_cases.map((item) => item.affine_add_p_plus_q);
  const oneMont = await module.fp.montOne();
  const oneFp2 = { c0_bytes_le: bytesToHex(oneMont), c1_bytes_le: bytesToHex(module.fp.zero()) };
  const zero = zeroFp2(g2.componentBytes);
  const jacInfinityWant = vectors.point_cases.map(() => ({ x: oneFp2, y: oneFp2, z: zero }));

  expectPointBatch("copy", await g2.copyBatch(pJacobian), vectors.point_cases.map((item) => item.p_jacobian), log);
  expectPointBatch("jac_infinity", await g2.jacobianInfinityBatch(vectors.point_cases.length), jacInfinityWant, log);
  expectPointBatch("affine_to_jac", await g2.affineToJacobianBatch(pAffine), vectors.point_cases.map((item) => item.p_jacobian), log);
  expectPointBatch("neg_jac", await g2.negJacobianBatch(pJacobian), negWant, log);
  expectAffineBatch("jac_to_affine", await g2.jacobianToAffineBatch(pJacobian), affineWant, log);
  expectPointBatch("double_jac", await g2.doubleJacobianBatch(pJacobian), doubleWant, log);
  expectPointBatch("add_mixed", await g2.addMixedBatch(pJacobian, qAffine), addWant, log);
  expectPointBatch("affine_add", await g2.affineAddBatch(pAffine, qAffine), affineAddWant, log);

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G2 browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
