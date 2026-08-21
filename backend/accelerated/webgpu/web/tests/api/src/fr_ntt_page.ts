export {};

import { bytesToHex, fetchJSON, hexToBytes } from "../../../src/curvegpu/browser_utils.js";
import type { CurveGPUElementBytes, CurveModule, SupportedCurveID } from "../../../src/index.js";
import { curveDisplayName } from "./shared/page_library.js";

type NTTCase = {
  name: string;
  size: number;
  input_mont_le: string[];
  forward_expected_le: string[];
  inverse_expected_le: string[];
  stage_twiddles_le: string[][];
  inverse_stage_twiddles_le: string[][];
  inverse_scale_le: string;
};

type FRNTTVectors = {
  ntt_cases: NTTCase[];
};

type NTTConfig = {
  curve: SupportedCurveID;
  title: string;
  vectorPath: string;
};

const CONFIGS: Partial<Record<SupportedCurveID, NTTConfig>> = {
  bn254: {
    curve: "bn254",
    title: "BN254 fr NTT Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bn254_fr_ntt.json",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 fr NTT Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bls12_377_fr_ntt.json",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 fr NTT Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bls12_381_fr_ntt.json",
  },
};

function bytesList(hexValues: readonly string[]): CurveGPUElementBytes[] {
  return hexValues.map(hexToBytes);
}

function expectHexBatch(name: string, got: readonly CurveGPUElementBytes[], want: readonly string[]): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = bytesToHex(got[i]);
    if (gotHex !== want[i]) {
      throw new Error(`${name}: mismatch at index ${i}: got=${gotHex} want=${want[i]}`);
    }
  }
}

export async function runSuite(module: CurveModule, log: (msg: string) => void): Promise<{ passed: number; failed: number }> {
  const config = CONFIGS[module.id];
  if (!config) {
    throw new Error(`fr NTT vectors unavailable for curve ${module.id}`);
  }
  log(`=== ${config.title} ===`);
  log("");
  const vectors = await fetchJSON<FRNTTVectors>(config.vectorPath);
  log(`cases.ntt = ${vectors.ntt_cases.length}`);

  for (const item of vectors.ntt_cases) {
    const input = bytesList(item.input_mont_le);
    const forward = await module.ntt.forward(input);
    expectHexBatch(`${item.name}: forward_ntt`, forward, item.forward_expected_le);
    const inverse = await module.ntt.inverse(forward);
    expectHexBatch(`${item.name}: inverse_ntt`, inverse, item.inverse_expected_le);
  }

  log("forward_ntt: OK");
  log("inverse_ntt: OK");
  log("");
  log(`PASS: ${curveDisplayName(module.id)} fr NTT browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
