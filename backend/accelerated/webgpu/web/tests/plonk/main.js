/* eslint-disable */

import "../../src/curvegpu/shader_bundle.generated.js";
import { createBLS12377, createBLS12381, createBN254, createCurveGPUContext, curveDefinition } from "../../index.js";

const implSelect = document.getElementById("impl");
const curveSelect = document.getElementById("curve");
const sizeLogSelect = document.getElementById("size-log");
const commitmentsSelect = document.getElementById("commitments");
const proveRunsInput = document.getElementById("prove-runs");
const runButton = document.getElementById("run");
const statusEl = document.getElementById("status");
const logEl = document.getElementById("log");
const SUPPORTED_CURVES = ["bn254", "bls12_377", "bls12_381"];

function appendLog(line = "") {
  logEl.textContent += `${line}\n`;
}

function clearLog() {
  logEl.textContent = "";
}

function setStatus(text) {
  statusEl.textContent = text;
}

function formatMs(value) {
  return Number(value).toFixed(3);
}

function readMs(result, key, fallback = 0) {
  if (result && typeof result[key] === "number") {
    return result[key];
  }
  return fallback;
}

function readConfig() {
  return {
    curve: curveSelect.value,
    sizeLog: Number.parseInt(sizeLogSelect.value, 10),
    commitments: Number.parseInt(commitmentsSelect.value, 10),
    proveRuns: Number.parseInt(proveRunsInput.value, 10),
  };
}

function applyQueryDefaults() {
  const params = new URLSearchParams(window.location.search);
  const impl = params.get("impl");
  const curve = params.get("curve");
  const sizeLog = params.get("size-log") ?? params.get("sizeLog");
  const commitments = params.get("commitments") ?? params.get("commitment-count") ?? params.get("commitmentCount");
  const proveRuns = params.get("prove-runs") ?? params.get("proveRuns");

  if (impl && ["both", "webgpu-go", "native-go"].includes(impl)) {
    implSelect.value = impl;
  }
  if (curve && SUPPORTED_CURVES.includes(curve)) {
    curveSelect.value = curve;
  }
  if (sizeLog && ["12", "15", "18"].includes(sizeLog)) {
    sizeLogSelect.value = sizeLog;
  }
  if (commitments && ["0", "1", "2"].includes(commitments)) {
    commitmentsSelect.value = commitments;
  }
  if (proveRuns) {
    proveRunsInput.value = proveRuns;
  }
}

function fixtureBasePath(config) {
  return `/tests/fixtures/plonk/${config.curve}/2pow${config.sizeLog}/commit${config.commitments}`;
}

async function fetchBytes(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`failed to fetch ${path}: ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

function computeOutput(modulus, x, y, depth) {
  let acc = x % modulus;
  const mul = y % modulus;
  for (let i = 0; i < depth; i++) {
    acc = (acc * mul + acc + x + 1n) % modulus;
  }
  return acc;
}

function targetConstraints(sizeLog) {
  return 1 << sizeLog;
}

function estimatedConstraints(steps, commitments) {
  return 4 * steps + commitments * (Math.floor(steps / 4) + 2);
}

function chainStepsForTarget(sizeLog, commitments) {
  const target = targetConstraints(sizeLog) - 4;
  const commitmentCount = Math.max(0, Math.min(2, commitments));
  let steps = 4;
  for (; ;) {
    const next = steps + 4;
    if (estimatedConstraints(next, commitmentCount) > target) {
      return steps;
    }
    steps = next;
  }
}

function buildWitnesses(curve, config) {
  const definition = curveDefinition(config.curve);
  if (!definition.frModulusHex) {
    throw new Error(`missing scalar modulus for ${config.curve}`);
  }
  const depth = chainStepsForTarget(config.sizeLog, config.commitments);
  const modulus = BigInt(definition.frModulusHex);
  const x = 3n;
  const y = 5n;
  const out = computeOutput(modulus, x, y, depth);
  return {
    depth,
    targetConstraints: targetConstraints(config.sizeLog),
    fullWitness: curve.plonk.encodeWitness([out, x, y], { publicCount: 1 }),
    publicWitness: curve.plonk.encodeWitness([out], { publicCount: 1 }),
  };
}

async function createCurve(config) {
  const context = await createCurveGPUContext();
  switch (config.curve) {
    case "bn254":
      return createBN254(context);
    case "bls12_377":
      return createBLS12377(context);
    case "bls12_381":
      return createBLS12381(context);
    default:
      throw new Error(`unsupported PLONK scaffold curve ${config.curve}`);
  }
}

async function loadFixture(curve, config) {
  const base = fixtureBasePath(config);
  const [ccsBytes, pkBytes, vkBytes] = await Promise.all([
    fetchBytes(`${base}/ccs.bin`),
    fetchBytes(`${base}/pk.bin`),
    fetchBytes(`${base}/vk.bin`),
  ]);
  const [ccs, pk, vk] = await Promise.all([
    curve.plonk.readConstraintSystem(ccsBytes),
    // Note: using "unsafe" as the proving key is trusted and this avoid subgroup membership checks
    curve.plonk.readProvingKey(pkBytes, { format: "unsafe" }),
    curve.plonk.readVerificationKey(vkBytes),
  ]);
  return { ccs, pk, vk };
}

async function disposeAll(handles) {
  await Promise.allSettled(handles.map((handle) => handle.dispose()));
}

async function runPlonkImpl(label, runtimeKind, curve, config) {
  appendLog(`--- ${label} ---`);
  appendLog(`=== ${runtimeKind === "webgpu" ? "TS -> WebGPU PLONK" : "TS -> Native PLONK"} (${config.curve}) ===`);
  appendLog(`fixture = 2^${config.sizeLog}`);
  appendLog(`commitments = ${config.commitments}`);
  appendLog(`prove_runs = ${config.proveRuns}`);

  const handles = [];
  const overallStart = performance.now();

  try {
    setStatus(`Loading ${label} runtime`);
    await curve.plonk.loadRuntime({ kind: runtimeKind });

    setStatus(`Loading ${label} fixture`);
    const fixtureStart = performance.now();
    const fixture = await loadFixture(curve, config);
    handles.push(fixture.ccs, fixture.pk, fixture.vk);
    const fixtureDuration = performance.now() - fixtureStart;
    appendLog(`fixture_load_ms = ${formatMs(fixtureDuration)}`);
    appendLog(`constraints = ${fixture.ccs.constraints}`);

    setStatus(`Building ${label} witness`);
    const witnessStart = performance.now();
    const { depth, targetConstraints, fullWitness, publicWitness } = buildWitnesses(curve, config);
    const witnessDuration = performance.now() - witnessStart;
    appendLog(`target_constraints = ${targetConstraints}`);
    appendLog(`chain_steps = ${depth}`);
    appendLog(`witness_build_ms = ${formatMs(witnessDuration)}`);

    setStatus(`Preparing ${label} proving key`);
    const prepareStart = performance.now();
    await curve.plonk.prepareProvingKey(fixture.pk, fixture.ccs);
    const prepareDuration = performance.now() - prepareStart;
    if (runtimeKind === "webgpu") {
      appendLog(`prepare_ms = ${formatMs(prepareDuration)}`);
    }

    const startupDuration = fixtureDuration + witnessDuration + (runtimeKind === "webgpu" ? prepareDuration : 0);
    appendLog(`startup_ms = ${formatMs(startupDuration)}`);

    let proveDuration = 0;
    let verifyDuration = 0;
    let proofSizeBytes = 0;
    let firstProofHash = "";

    const steadyStateStart = performance.now();
    for (let i = 0; i < config.proveRuns; i++) {
      setStatus(`Proving ${label} round ${i + 1}/${config.proveRuns}`);
      const proveStart = performance.now();
      const proofBytes = await curve.plonk.prove(fixture.ccs, fixture.pk, fullWitness);
      const roundProveDuration = performance.now() - proveStart;
      proveDuration += roundProveDuration;
      appendLog(`prove_round_${i}_ms = ${formatMs(roundProveDuration)}`);

      const verifyStart = performance.now();
      const verified = await curve.plonk.verify(proofBytes, fixture.vk, publicWitness);
      const roundVerifyDuration = performance.now() - verifyStart;
      verifyDuration += roundVerifyDuration;
      if (!verified) {
        throw new Error(`verify round ${i}: proof rejected`);
      }

      if (proofSizeBytes === 0) {
        proofSizeBytes = proofBytes.byteLength;
        appendLog(`proof_size_bytes = ${proofSizeBytes}`);
      }
      appendLog(`roundtrip_verify_round_${i} = OK`);
    }

    const steadyStateDuration = performance.now() - steadyStateStart;
    const overallDuration = performance.now() - overallStart;

    appendLog(`prove_total_ms = ${formatMs(proveDuration)}`);
    appendLog(`prove_avg_ms = ${formatMs(proveDuration / config.proveRuns)}`);
    appendLog(`verify_total_ms = ${formatMs(verifyDuration)}`);
    appendLog(`verify_avg_ms = ${formatMs(verifyDuration / config.proveRuns)}`);
    appendLog(`steady_state_total_ms = ${formatMs(steadyStateDuration)}`);
    appendLog(`overall_total_ms = ${formatMs(overallDuration)}`);

    return {
      impl: label,
      curve: config.curve,
      prove_runs: config.proveRuns,
      constraints: fixture.ccs.constraints,
      size_log: config.sizeLog,
      commitments: config.commitments,
      target_constraints: targetConstraints,
      depth_size: depth,
      fixture_duration_ms: fixtureDuration,
      witness_duration_ms: witnessDuration,
      prepare_duration_ms: runtimeKind === "webgpu" ? prepareDuration : 0,
      startup_duration_ms: startupDuration,
      prove_duration_ms: proveDuration,
      verify_duration_ms: verifyDuration,
      steady_state_duration_ms: steadyStateDuration,
      overall_duration_ms: overallDuration,
      proof_size_bytes: proofSizeBytes,
      roundtrip_verify_succeeded: true,
    };
  } finally {
    await disposeAll(handles);
  }
}

function compareResults(webgpu, nativeImpl) {
  appendLog("");
  appendLog("--- comparison ---");
  appendLog(`curve: ${webgpu.curve}`);
  appendLog(`fixture: 2^${webgpu.size_log}`);
  appendLog(`commitments: ${webgpu.commitments}`);
  appendLog(`target constraints: ${webgpu.target_constraints}`);
  appendLog(`depth: ${webgpu.depth_size}`);
  appendLog(`prove runs: ${webgpu.prove_runs}`);
  appendLog(`constraints: ${webgpu.constraints}`);
  appendLog(`roundtrip verify: webgpu=${webgpu.roundtrip_verify_succeeded} native=${nativeImpl.roundtrip_verify_succeeded}`);
  appendLog(`proof size bytes: webgpu=${webgpu.proof_size_bytes} native=${nativeImpl.proof_size_bytes}`);
  appendLog(`startup ms: webgpu=${formatMs(webgpu.startup_duration_ms)} native=${formatMs(nativeImpl.startup_duration_ms)}`);
  appendLog(`startup breakdown: webgpu fixture=${formatMs(readMs(webgpu, "fixture_duration_ms"))} witness=${formatMs(readMs(webgpu, "witness_duration_ms"))} prepare=${formatMs(readMs(webgpu, "prepare_duration_ms"))} | native fixture=${formatMs(readMs(nativeImpl, "fixture_duration_ms"))} witness=${formatMs(readMs(nativeImpl, "witness_duration_ms"))}`);
  appendLog(`steady-state total ms: webgpu=${formatMs(webgpu.steady_state_duration_ms)} native=${formatMs(nativeImpl.steady_state_duration_ms)}`);
  appendLog(`overall total ms: webgpu=${formatMs(webgpu.overall_duration_ms)} native=${formatMs(nativeImpl.overall_duration_ms)}`);
  appendLog(`prove avg ms: webgpu=${formatMs(webgpu.prove_duration_ms / webgpu.prove_runs)} native=${formatMs(nativeImpl.prove_duration_ms / nativeImpl.prove_runs)}`);
  appendLog(`verify avg ms: webgpu=${formatMs(webgpu.verify_duration_ms / webgpu.prove_runs)} native=${formatMs(nativeImpl.verify_duration_ms / nativeImpl.prove_runs)}`);
}

async function runSelected() {
  clearLog();
  runButton.disabled = true;
  const impl = implSelect.value;
  const config = readConfig();

  appendLog("=== PLONK TS Browser POC ===");
  appendLog(`impl = ${impl}`);
  appendLog(`curve = ${config.curve}`);
  appendLog(`fixture = 2^${config.sizeLog}`);
  appendLog(`commitments = ${config.commitments}`);
  appendLog(`prove_runs = ${config.proveRuns}`);
  appendLog("");

  setStatus("Initializing curve module");
  try {
    const curve = await createCurve(config);
    let webgpuResult = null;
    let nativeResult = null;

    if (impl === "webgpu-go" || impl === "both") {
      webgpuResult = await runPlonkImpl("webgpu-go", "webgpu", curve, config);
    }
    if (impl === "native-go" || impl === "both") {
      nativeResult = await runPlonkImpl("native-go", "native", curve, config);
    }
    if (webgpuResult && nativeResult) {
      compareResults(webgpuResult, nativeResult);
    }
    setStatus("PASS");
  } catch (error) {
    setStatus("FAIL");
    appendLog("");
    appendLog(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
    throw error;
  } finally {
    runButton.disabled = false;
  }
}

runButton.addEventListener("click", () => {
  void runSelected();
});

applyQueryDefaults();

if (new URLSearchParams(window.location.search).get("autorun") === "1") {
  void runSelected();
}
