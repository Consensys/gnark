export { };

import { bytesToHex, fetchJSON, hexToBytes } from "../../../src/curvegpu/browser_utils.js";
import type { CurveGPUElementBytes, CurveModule, FieldModule, SupportedCurveID } from "../../../src/index.js";
import { curveDisplayName } from "./shared/page_library.js";

type ElementCase = {
  name: string;
  a_bytes_le: string;
  b_bytes_le: string;
  equal_bytes_le: string;
  add_bytes_le: string;
  sub_bytes_le: string;
  neg_a_bytes_le: string;
  double_a_bytes_le: string;
  mul_bytes_le: string;
  square_a_bytes_le: string;
};

type NormalizeCase = {
  name: string;
  input_bytes_le: string;
  expected_bytes_le: string;
};

type ConvertCase = {
  name: string;
  regular_bytes_le: string;
  mont_bytes_le: string;
};

type FROpsVectors = {
  element_cases: ElementCase[];
  edge_cases: ElementCase[];
  differential_cases: ElementCase[];
  normalize_cases: NormalizeCase[];
  convert_cases: ConvertCase[];
};

type FrOpsConfig = {
  curve: SupportedCurveID;
  title: string;
  vectorPath: string;
};

const CONFIGS: Partial<Record<SupportedCurveID, FrOpsConfig>> = {
  bn254: {
    curve: "bn254",
    title: "BN254 fr Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bn254_fr_ops.json",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 fr Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bls12_377_fr_ops.json",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 fr Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bls12_381_fr_ops.json",
  },
};

function combineElementCases(vectors: FROpsVectors): ElementCase[] {
  return [...vectors.element_cases, ...vectors.edge_cases, ...vectors.differential_cases];
}

function zeroHex(byteSize: number): string {
  return bytesToHex(new Uint8Array(byteSize));
}

function isNonZeroHex(hex: string): boolean {
  return hexToBytes(hex).some((byte) => byte !== 0);
}

function bytesList(hexValues: readonly string[]): Uint8Array[] {
  return hexValues.map(hexToBytes);
}

function expectHexBatch(name: string, got: readonly CurveGPUElementBytes[], wantHex: readonly string[], log: (msg: string) => void): void {
  if (got.length !== wantHex.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${wantHex.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    const gotHex = bytesToHex(got[i]);
    if (gotHex !== wantHex[i]) {
      throw new Error(`${name}: mismatch at index ${i}: got=${gotHex} want=${wantHex[i]}`);
    }
  }
  log(`${name}: OK`);
}

function expectBoolBatch(name: string, got: readonly boolean[], want: readonly boolean[], log: (msg: string) => void): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    if (got[i] !== want[i]) {
      throw new Error(`${name}: mismatch at index ${i}: got=${String(got[i])} want=${String(want[i])}`);
    }
  }
  log(`${name}: OK`);
}

function mustFindConvertCase(cases: readonly ConvertCase[], name: string): ConvertCase {
  const found = cases.find((item) => item.name === name);
  if (!found) {
    throw new Error(`missing convert case ${name}`);
  }
  return found;
}

export async function runSuite(module: CurveModule, log: (msg: string) => void): Promise<{ passed: number; failed: number }> {
  const config = CONFIGS[module.id];
  if (!config) {
    throw new Error(`fr ops vectors unavailable for curve ${module.id}`);
  }
  log(`=== ${config.title} ===`);
  log("");
  const vectors = await fetchJSON<FROpsVectors>(config.vectorPath);
  log(`cases.sanity = ${vectors.element_cases.length}`);
  log(`cases.edge = ${vectors.edge_cases.length}`);
  log(`cases.differential = ${vectors.differential_cases.length}`);
  log(`cases.normalize = ${vectors.normalize_cases.length}`);
  log(`cases.convert = ${vectors.convert_cases.length}`);

  const fr: FieldModule = module.fr;
  const elementCases = combineElementCases(vectors);
  const aHex = elementCases.map((item) => item.a_bytes_le);
  const bHex = elementCases.map((item) => item.b_bytes_le);
  const aBytes = bytesList(aHex);
  const bBytes = bytesList(bHex);
  const zeroHexValue = zeroHex(fr.byteSize);
  const oneMontHex = bytesToHex(await fr.montOne());

  expectHexBatch("copy", await fr.copyBatch(aBytes), aHex, log);
  expectBoolBatch("equal", await fr.equalBatch(aBytes, bBytes), elementCases.map((item) => isNonZeroHex(item.equal_bytes_le)), log);
  expectHexBatch("zero", Array.from({ length: elementCases.length }, () => fr.zero()), Array.from({ length: elementCases.length }, () => zeroHexValue), log);
  const oneBatch = Array.from({ length: elementCases.length }, () => hexToBytes(oneMontHex));
  expectHexBatch("one", oneBatch, Array.from({ length: elementCases.length }, () => oneMontHex), log);
  expectHexBatch("add", await fr.addBatch(aBytes, bBytes), elementCases.map((item) => item.add_bytes_le), log);
  expectHexBatch("sub", await fr.subBatch(aBytes, bBytes), elementCases.map((item) => item.sub_bytes_le), log);
  expectHexBatch("neg", await fr.negBatch(aBytes), elementCases.map((item) => item.neg_a_bytes_le), log);
  expectHexBatch("double", await fr.doubleBatch(aBytes), elementCases.map((item) => item.double_a_bytes_le), log);
  expectHexBatch("mul", await fr.mulBatch(aBytes, bBytes), elementCases.map((item) => item.mul_bytes_le), log);
  expectHexBatch("square", await fr.squareBatch(aBytes), elementCases.map((item) => item.square_a_bytes_le), log);
  expectHexBatch(
    "to_mont",
    await fr.toMontgomeryBatch(bytesList(vectors.convert_cases.map((item) => item.regular_bytes_le))),
    vectors.convert_cases.map((item) => item.mont_bytes_le),
    log,
  );
  expectHexBatch(
    "from_mont",
    await fr.fromMontgomeryBatch(bytesList(vectors.convert_cases.map((item) => item.mont_bytes_le))),
    vectors.convert_cases.map((item) => item.regular_bytes_le),
    log,
  );
  expectHexBatch(
    "normalize",
    await fr.normalizeMontBatch(bytesList(vectors.normalize_cases.map((item) => item.input_bytes_le))),
    vectors.normalize_cases.map((item) => item.expected_bytes_le),
    log,
  );

  const oneCase = mustFindConvertCase(vectors.convert_cases, "one");
  const oneHexExpected = bytesToHex(await fr.montOne());
  if (oneHexExpected !== oneCase.mont_bytes_le) {
    throw new Error(`one: mismatch got=${oneHexExpected} want=${oneCase.mont_bytes_le}`);
  }

  log("");
  log(`PASS: ${curveDisplayName(module.id)} fr browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
