import {
  appendAdapterDiagnostics,
  createPageUI,
  fetchText,
  mustElement,
} from "../../../src/curvegpu/browser_utils.js";

const FR_OP_TO_MONT = 11;

const FR_VECTOR_OP_ADD = 1;
const FR_VECTOR_OP_SUB = 2;
const FR_VECTOR_OP_MUL_FACTORS = 3;
const FR_VECTOR_OP_BIT_REVERSE_COPY = 4;

const ELEMENT_WORDS = 8;
const ELEMENT_BYTES = 32;
const UNIFORM_BYTES = 32;

type BenchConfig = {
  curve: string;
  title: string;
  arithShaderPath: string;
  vectorShaderPath: string;
  arithLabel: string;
  vectorLabel: string;
};

type Kernel = {
  pipeline: GPUComputePipeline;
  bindGroupLayout: GPUBindGroupLayout;
};

type Profile = {
  uploadMs: number;
  kernelMs: number;
  readbackMs: number;
  totalMs: number;
};

declare const GPUShaderStage: {
  COMPUTE: number;
};

declare const GPUBufferUsage: {
  STORAGE: number;
  COPY_DST: number;
  COPY_SRC: number;
  MAP_READ: number;
  UNIFORM: number;
};

declare const GPUMapMode: {
  READ: number;
};

const minLogEl = document.getElementById("min-log") as HTMLInputElement | null;
const maxLogEl = document.getElementById("max-log") as HTMLInputElement | null;
const itersEl = document.getElementById("iters") as HTMLInputElement | null;
const runButton = document.getElementById("run") as HTMLButtonElement | null;
const statusEl = document.getElementById("status") as HTMLElement | null;
const logEl = document.getElementById("log") as HTMLElement | null;
const { setStatus, setPageState, writeLog } = createPageUI(statusEl, logEl);

const CONFIGS: Record<string, BenchConfig> = {
  bn254: {
    curve: "bn254",
    title: "BN254 fr Vector Browser Benchmark",
    arithShaderPath: "/shaders/curves/bn254/fr_arith.wgsl",
    vectorShaderPath: "/shaders/curves/bn254/fr_vector.wgsl",
    arithLabel: "bn254-fr",
    vectorLabel: "bn254-fr-vector",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 fr Vector Browser Benchmark",
    arithShaderPath: "/shaders/curves/bls12_377/fr_arith.wgsl",
    vectorShaderPath: "/shaders/curves/bls12_377/fr_vector.wgsl",
    arithLabel: "bls12-377-fr",
    vectorLabel: "bls12-377-fr-vector",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 fr Vector Browser Benchmark",
    arithShaderPath: "/shaders/curves/bls12_381/fr_arith.wgsl",
    vectorShaderPath: "/shaders/curves/bls12_381/fr_vector.wgsl",
    arithLabel: "bls12-381-fr",
    vectorLabel: "bls12-381-fr-vector",
  },
};

function getConfig(): BenchConfig {
  const curve = new URLSearchParams(window.location.search).get("curve") ?? "bn254";
  const config = CONFIGS[curve];
  if (!config) {
    throw new Error(`unsupported curve: ${curve}`);
  }
  return config;
}

function createKernel(device: GPUDevice, label: string, shaderCode: string, entryPoint: string): Kernel {
  const shaderModule = device.createShaderModule({ label: `${label}-shader`, code: shaderCode });
  const bindGroupLayout = device.createBindGroupLayout({
    label: `${label}-bgl`,
    entries: [
      { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
      { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: "uniform" } },
    ],
  });
  const pipelineLayout = device.createPipelineLayout({
    label: `${label}-pl`,
    bindGroupLayouts: [bindGroupLayout],
  });
  const pipeline = device.createComputePipeline({
    label: `${label}-pipeline`,
    layout: pipelineLayout,
    compute: { module: shaderModule, entryPoint },
  });
  return { pipeline, bindGroupLayout };
}

function makeRegularBatch(count: number, seed: number): Uint32Array {
  const words = new Uint32Array(count * ELEMENT_WORDS);
  let state = seed >>> 0;
  for (let i = 0; i < count; i += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    words[i * ELEMENT_WORDS + 0] = state >>> 0;
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    words[i * ELEMENT_WORDS + 1] = state >>> 0;
  }
  return words;
}

function makeZeroBatch(count: number): Uint32Array {
  return new Uint32Array(count * ELEMENT_WORDS);
}

async function runFullPathBenchmark(
  device: GPUDevice,
  kernel: Kernel,
  inputA: Uint32Array,
  inputB: Uint32Array,
  opcode: number,
  logCount: number,
): Promise<{ out: Uint32Array; profile: Profile }> {
  const count = inputA.byteLength / ELEMENT_BYTES;
  const dataBytes = inputA.byteLength;
  const totalStart = performance.now();
  const inputABuffer = device.createBuffer({
    label: "input-a",
    size: dataBytes,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
  });
  const inputBBuffer = device.createBuffer({
    label: "input-b",
    size: dataBytes,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
  });
  const outputBuffer = device.createBuffer({
    label: "output",
    size: dataBytes,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC,
  });
  const stagingBuffer = device.createBuffer({
    label: "staging",
    size: dataBytes,
    usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ,
  });
  const uniformBuffer = device.createBuffer({
    label: "params",
    size: UNIFORM_BYTES,
    usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
  });

  const uploadStart = performance.now();
  device.queue.writeBuffer(inputABuffer, 0, inputA.buffer, inputA.byteOffset, inputA.byteLength);
  device.queue.writeBuffer(inputBBuffer, 0, inputB.buffer, inputB.byteOffset, inputB.byteLength);
  const params = new Uint32Array(UNIFORM_BYTES / 4);
  params[0] = count;
  params[1] = opcode;
  params[2] = logCount;
  device.queue.writeBuffer(uniformBuffer, 0, params);

  const bindGroup = device.createBindGroup({
    label: "bind-group",
    layout: kernel.bindGroupLayout,
    entries: [
      { binding: 0, resource: { buffer: inputABuffer } },
      { binding: 1, resource: { buffer: inputBBuffer } },
      { binding: 2, resource: { buffer: outputBuffer } },
      { binding: 3, resource: { buffer: uniformBuffer } },
    ],
  });
  const uploadMs = performance.now() - uploadStart;

  const kernelStart = performance.now();
  const encoder = device.createCommandEncoder({ label: "encoder" });
  const pass = encoder.beginComputePass({ label: "pass" });
  pass.setPipeline(kernel.pipeline);
  pass.setBindGroup(0, bindGroup);
  pass.dispatchWorkgroups(Math.ceil(count / 64));
  pass.end();
  encoder.copyBufferToBuffer(outputBuffer, 0, stagingBuffer, 0, dataBytes);
  device.queue.submit([encoder.finish()]);
  const kernelMs = performance.now() - kernelStart;

  const readbackStart = performance.now();
  await stagingBuffer.mapAsync(GPUMapMode.READ);
  const out = new Uint32Array(stagingBuffer.getMappedRange().slice(0));
  stagingBuffer.unmap();
  const readbackMs = performance.now() - readbackStart;

  inputABuffer.destroy();
  inputBBuffer.destroy();
  outputBuffer.destroy();
  stagingBuffer.destroy();
  uniformBuffer.destroy();

  return {
    out,
    profile: {
      uploadMs,
      kernelMs,
      readbackMs,
      totalMs: performance.now() - totalStart,
    },
  };
}

async function toMontBatch(device: GPUDevice, arithKernel: Kernel, regularWords: Uint32Array): Promise<Uint32Array> {
  const zeros = makeZeroBatch(regularWords.byteLength / ELEMENT_BYTES);
  return (await runFullPathBenchmark(device, arithKernel, regularWords, zeros, FR_OP_TO_MONT, 0)).out;
}

async function benchOp(
  device: GPUDevice,
  kernel: Kernel,
  inputA: Uint32Array,
  inputB: Uint32Array,
  opcode: number,
  logCount: number,
  iters: number,
): Promise<{ cold: Profile; warm: Profile }> {
  const cold = await runFullPathBenchmark(device, kernel, inputA, inputB, opcode, logCount);
  if (iters === 1) {
    return { cold: cold.profile, warm: cold.profile };
  }
  let uploadMs = 0;
  let kernelMs = 0;
  let readbackMs = 0;
  let totalMs = 0;
  for (let i = 0; i < iters; i += 1) {
    const warm = await runFullPathBenchmark(device, kernel, inputA, inputB, opcode, logCount);
    uploadMs += warm.profile.uploadMs;
    kernelMs += warm.profile.kernelMs;
    readbackMs += warm.profile.readbackMs;
    totalMs += warm.profile.totalMs;
  }
  return {
    cold: cold.profile,
    warm: {
      uploadMs: uploadMs / iters,
      kernelMs: kernelMs / iters,
      readbackMs: readbackMs / iters,
      totalMs: totalMs / iters,
    },
  };
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
    if (!navigator.gpu) {
      throw new Error("WebGPU is not available in this browser");
    }

    const initStart = performance.now();
    lines.push("1. Requesting adapter... OK");
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) {
      throw new Error("requestAdapter returned null");
    }
    await appendAdapterDiagnostics(adapter, lines);
    lines.push("2. Requesting device... OK");
    const device = await adapter.requestDevice();

    const [arithShader, vectorShader] = await Promise.all([
      fetchText(config.arithShaderPath),
      fetchText(config.vectorShaderPath),
    ]);
    lines.push("3. Loading shaders... OK");

    const arithKernel = createKernel(device, config.arithLabel, arithShader, "fr_ops_main");
    const vectorKernel = createKernel(device, config.vectorLabel, vectorShader, "fr_vector_main");
    const initElapsed = performance.now() - initStart;
    lines.push("4. Creating pipelines... OK");
    lines.push(`init_ms = ${initElapsed.toFixed(3)}`);
    lines.push("");
    lines.push("size,op,init_ms,cold_upload_ms,cold_kernel_ms,cold_readback_ms,cold_total_ms,cold_with_init_ms,warm_upload_ms,warm_kernel_ms,warm_readback_ms,warm_total_ms");

    for (let logSize = minLog; logSize <= maxLog; logSize += 1) {
      const size = 1 << logSize;
      const leftRegular = makeRegularBatch(size, 0x12345678 ^ size);
      const rightRegular = makeRegularBatch(size, 0x9e3779b9 ^ size);
      const zeros = makeZeroBatch(size);

      const leftMont = await toMontBatch(device, arithKernel, leftRegular);
      const rightMont = await toMontBatch(device, arithKernel, rightRegular);

      const addBench = await benchOp(device, vectorKernel, leftMont, rightMont, FR_VECTOR_OP_ADD, 0, iters);
      lines.push(`${size},add,${initElapsed.toFixed(3)},${addBench.cold.uploadMs.toFixed(3)},${addBench.cold.kernelMs.toFixed(3)},${addBench.cold.readbackMs.toFixed(3)},${addBench.cold.totalMs.toFixed(3)},${(initElapsed + addBench.cold.totalMs).toFixed(3)},${addBench.warm.uploadMs.toFixed(3)},${addBench.warm.kernelMs.toFixed(3)},${addBench.warm.readbackMs.toFixed(3)},${addBench.warm.totalMs.toFixed(3)}`);

      const subBench = await benchOp(device, vectorKernel, leftMont, rightMont, FR_VECTOR_OP_SUB, 0, iters);
      lines.push(`${size},sub,${initElapsed.toFixed(3)},${subBench.cold.uploadMs.toFixed(3)},${subBench.cold.kernelMs.toFixed(3)},${subBench.cold.readbackMs.toFixed(3)},${subBench.cold.totalMs.toFixed(3)},${(initElapsed + subBench.cold.totalMs).toFixed(3)},${subBench.warm.uploadMs.toFixed(3)},${subBench.warm.kernelMs.toFixed(3)},${subBench.warm.readbackMs.toFixed(3)},${subBench.warm.totalMs.toFixed(3)}`);

      const mulBench = await benchOp(device, vectorKernel, leftMont, rightMont, FR_VECTOR_OP_MUL_FACTORS, 0, iters);
      lines.push(`${size},mul,${initElapsed.toFixed(3)},${mulBench.cold.uploadMs.toFixed(3)},${mulBench.cold.kernelMs.toFixed(3)},${mulBench.cold.readbackMs.toFixed(3)},${mulBench.cold.totalMs.toFixed(3)},${(initElapsed + mulBench.cold.totalMs).toFixed(3)},${mulBench.warm.uploadMs.toFixed(3)},${mulBench.warm.kernelMs.toFixed(3)},${mulBench.warm.readbackMs.toFixed(3)},${mulBench.warm.totalMs.toFixed(3)}`);

      const bitReverseBench = await benchOp(device, vectorKernel, leftMont, zeros, FR_VECTOR_OP_BIT_REVERSE_COPY, logSize, iters);
      lines.push(`${size},bit_reverse,${initElapsed.toFixed(3)},${bitReverseBench.cold.uploadMs.toFixed(3)},${bitReverseBench.cold.kernelMs.toFixed(3)},${bitReverseBench.cold.readbackMs.toFixed(3)},${bitReverseBench.cold.totalMs.toFixed(3)},${(initElapsed + bitReverseBench.cold.totalMs).toFixed(3)},${bitReverseBench.warm.uploadMs.toFixed(3)},${bitReverseBench.warm.kernelMs.toFixed(3)},${bitReverseBench.warm.readbackMs.toFixed(3)},${bitReverseBench.warm.totalMs.toFixed(3)}`);
      writeLog(lines);
    }

    lines.push("");
    lines.push(`PASS: ${config.curve} fr vector browser benchmark completed`);
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

export {};
