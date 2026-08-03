export { };

import {
  bytesToHex,
  createPageUI,
  fetchJSON,
  hexToBytes,
  mustElement,
} from "../../../src/curvegpu/browser_utils.js";
import { benchmarkTotalDuration } from "./shared/bench_total.js";
import { createPreferredByteBaseSource } from "../../../src/curvegpu/msm_bench_sources.js";
import { makeRandomScalarBatch } from "../../../src/curvegpu/msm_shared.js";
import type {
  CurveGPUAffinePoint,
  CurveGPUElementBytes,
  CurveGPUJacobianPoint,
  CurveModule,
  SupportedCurveID,
} from "../../../src/index.js";
import { appendContextDiagnostics, createRequestedCurveModule, getRequestedCurveId } from "./shared/page_library.js";

type AffinePoint = {
  x_bytes_le: string;
  y_bytes_le: string;
};

type G1ScalarMulVectors = {
  generator_affine: AffinePoint;
  one_mont_z: string;
};

type CurveBenchConfig = {
  curve: SupportedCurveID;
  title: string;
  successMessage: string;
  coordinateBytes: number;
  pointBytes: number;
  scalarVectorsPath: string;
  fixtureJSONPath?: string;
  fixtureBinPath?: string;
};

const CURVE_CONFIGS: Partial<Record<SupportedCurveID, CurveBenchConfig>> = {
  bn254: {
    curve: "bn254",
    title: "BN254 G1 MSM Browser Benchmark",
    successMessage: "BN254 G1 MSM browser benchmark completed",
    coordinateBytes: 32,
    pointBytes: 96,
    scalarVectorsPath: "/tests/fixtures/api/vectors/g1/bn254_g1_scalar_mul.json",
    fixtureJSONPath: "/tests/fixtures/api/fixtures/g1/bn254_bases_jacobian.json",
    fixtureBinPath: "/tests/fixtures/api/fixtures/g1/bn254_bases_jacobian.bin",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 G1 MSM Browser Benchmark",
    successMessage: "BLS12-377 G1 MSM browser benchmark completed",
    coordinateBytes: 48,
    pointBytes: 144,
    scalarVectorsPath: "/tests/fixtures/api/vectors/g1/bls12_377_g1_scalar_mul.json",
    fixtureJSONPath: "/tests/fixtures/api/fixtures/g1/bls12_377_bases_jacobian.json",
    fixtureBinPath: "/tests/fixtures/api/fixtures/g1/bls12_377_bases_jacobian.bin",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 G1 MSM Browser Benchmark",
    successMessage: "BLS12-381 G1 MSM browser benchmark completed",
    coordinateBytes: 48,
    pointBytes: 144,
    scalarVectorsPath: "/tests/fixtures/api/vectors/g1/bls12_381_g1_scalar_mul.json",
    fixtureJSONPath: "/tests/fixtures/api/fixtures/g1/bls12_381_bases_jacobian.json",
    fixtureBinPath: "/tests/fixtures/api/fixtures/g1/bls12_381_bases_jacobian.bin",
  },
};

const minLogEl = document.getElementById("min-log") as HTMLInputElement | null;
const maxLogEl = document.getElementById("max-log") as HTMLInputElement | null;
const itersEl = document.getElementById("iters") as HTMLInputElement | null;
const runButton = document.getElementById("run") as HTMLButtonElement | null;
const statusEl = document.getElementById("status") as HTMLElement | null;
const logEl = document.getElementById("log") as HTMLElement | null;
const { setStatus, setPageState, writeLog } = createPageUI(statusEl, logEl);

function getConfig(): CurveBenchConfig {
  const curve = getRequestedCurveId();
  const config = CURVE_CONFIGS[curve];
  if (!config) {
    throw new Error(`g1 MSM benchmark unavailable for curve ${curve}`);
  }
  return config;
}

function affineFromHex(point: AffinePoint): CurveGPUAffinePoint {
  return { x: hexToBytes(point.x_bytes_le), y: hexToBytes(point.y_bytes_le) };
}

function makeScalarHexLEFromUint64(value: bigint): string {
  const out = new Uint8Array(32);
  let x = value;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return bytesToHex(out);
}

function packJacobianPoints(
  points: readonly CurveGPUJacobianPoint[],
  coordinateBytes: number,
  pointBytes: number,
): Uint8Array {
  const out = new Uint8Array(points.length * pointBytes);
  points.forEach((point, index) => {
    const base = index * pointBytes;
    out.set(point.x, base);
    out.set(point.y, base + coordinateBytes);
    out.set(point.z, base + 2 * coordinateBytes);
  });
  return out;
}

function unpackAffineBases(
  bytes: Uint8Array,
  count: number,
  coordinateBytes: number,
  pointBytes: number,
): CurveGPUAffinePoint[] {
  const out: CurveGPUAffinePoint[] = [];
  for (let i = 0; i < count; i += 1) {
    const base = i * pointBytes;
    out.push({
      x: bytes.slice(base, base + coordinateBytes),
      y: bytes.slice(base + coordinateBytes, base + 2 * coordinateBytes),
    });
  }
  return out;
}

function makeMSMScalars(count: number): CurveGPUElementBytes[] {
  return makeRandomScalarBatch(count).hexes.map((hex) => hexToBytes(hex) as CurveGPUElementBytes);
}

function fixtureGenerationHint(curve: SupportedCurveID, size: number): string {
  return `make fixture-${curve}-g1 COUNT=${size}`;
}

async function buildGeneratedBases(
  curve: CurveModule,
  coordinateBytes: number,
  pointBytes: number,
  generator: CurveGPUAffinePoint,
  count: number,
): Promise<Uint8Array> {
  const bases = Array.from({ length: count }, () => generator);
  const scalars = Array.from({ length: count }, (_, index) => hexToBytes(makeScalarHexLEFromUint64(BigInt(index + 1))) as CurveGPUElementBytes);
  const generated = await curve.g1.scalarMulAffineBatch(bases, scalars);
  return packJacobianPoints(generated, coordinateBytes, pointBytes);
}

async function runBenchmark(): Promise<void> {
  const config = getConfig();
  const lines = [`=== ${config.title} ===`, ""];
  writeLog(lines);
  setStatus("Running");
  setPageState("running");
  mustElement(runButton, "run").disabled = true;

  try {
    const minLog = Number.parseInt(mustElement(minLogEl, "min-log").value, 10);
    const maxLog = Number.parseInt(mustElement(maxLogEl, "max-log").value, 10);
    const iters = Number.parseInt(mustElement(itersEl, "iters").value, 10);
    if (!Number.isInteger(minLog) || !Number.isInteger(maxLog) || !Number.isInteger(iters) || minLog < 1 || maxLog < minLog || iters < 1) {
      throw new Error("invalid benchmark controls");
    }

    const initStart = performance.now();
    const curve = await createRequestedCurveModule(config.curve);
    const scalarVectors = await fetchJSON<G1ScalarMulVectors>(config.scalarVectorsPath);
    const generator = affineFromHex(scalarVectors.generator_affine);
    const baseSourceProvider = createPreferredByteBaseSource({
      locationSearch: window.location.search,
      pointBytes: config.pointBytes,
      fixtureJSONPath: config.fixtureJSONPath,
      fixtureBinPath: config.fixtureBinPath,
      generatedLoadBases: async (size) => buildGeneratedBases(curve, config.coordinateBytes, config.pointBytes, generator, size),
      generateHint: (size) => fixtureGenerationHint(config.curve, size <= 0 ? (1 << 19) : size),
    });
    const baseSourceInit = await baseSourceProvider.init();
    const initMs = performance.now() - initStart;

    lines.push("1. Requesting adapter... OK");
    appendContextDiagnostics(lines, curve.context);
    lines.push("2. Requesting device... OK");
    lines.push(`3. Loading base source... OK (${baseSourceInit.context.baseSource})`);
    lines.push(`init_ms = ${initMs.toFixed(3)}`);
    if (baseSourceInit.postMetricLines) {
      lines.push(...baseSourceInit.postMetricLines);
    }
    lines.push("");
    lines.push("size,op,window,init_ms,prep_ms,cold_total_ms,cold_with_init_prep_ms,warm_total_ms");
    writeLog(lines);

    for (let logSize = minLog; logSize <= maxLog; logSize += 1) {
      const size = 1 << logSize;
      const prepStart = performance.now();
      const { bases: baseBytes } = await baseSourceProvider.loadBases({
        context: baseSourceInit.context,
        size,
      });
      const bases = unpackAffineBases(baseBytes, size, config.coordinateBytes, config.pointBytes);
      const scalars = makeMSMScalars(size);
      const prepMs = performance.now() - prepStart;
      const window = curve.g1msm.bestWindow(size);
      const benchmark = await benchmarkTotalDuration(iters, async () => {
        await curve.g1msm.pippengerAffine(bases, scalars, {
          termsPerInstance: size,
          window,
        });
      });
      lines.push(
        [
          `${size}`,
          "msm_jac_pippenger_affine_input",
          `${window}`,
          initMs.toFixed(3),
          prepMs.toFixed(3),
          benchmark.coldMs.toFixed(3),
          (initMs + prepMs + benchmark.coldMs).toFixed(3),
          benchmark.warmMs.toFixed(3),
        ].join(","),
      );
      writeLog(lines);
    }

    lines.push("");
    lines.push(`PASS: ${config.successMessage}`);
    writeLog(lines);
    setStatus("Pass");
    setPageState("pass");
  } catch (error) {
    lines.push(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
    writeLog(lines);
    setStatus("Fail");
    setPageState("fail");
  } finally {
    mustElement(runButton, "run").disabled = false;
  }
}

mustElement(runButton, "run").addEventListener("click", () => {
  void runBenchmark();
});
