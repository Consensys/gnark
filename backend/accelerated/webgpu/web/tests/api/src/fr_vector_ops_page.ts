export {};

import {
  bytesToHex,
  fetchText,
  hexToBytes,
} from "../../../src/curvegpu/browser_utils.js";
import type { CurveModule } from "../../../src/index.js";

type VectorConfig = {
  curve: string;
  title: string;
  vectorPath: string;
  arithShaderPath: string;
  vectorShaderPath: string;
  arithLabel: string;
  vectorLabel: string;
};

type VectorCase = {
  name: string;
  regular_inputs_le: string[];
  mont_inputs_le: string[];
  mont_factors_le: string[];
  add_expected_le: string[];
  sub_expected_le: string[];
  mul_expected_le: string[];
  to_mont_expected_le: string[];
  from_mont_expected_le: string[];
  bit_reverse_expected_le: string[];
};

type FRVectorOpsVectors = {
  vector_cases: VectorCase[];
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

const FR_OP_ADD = 3;
const FR_OP_SUB = 4;
const FR_OP_MUL = 9;
const FR_OP_TO_MONT = 11;
const FR_OP_FROM_MONT = 12;

const FR_VECTOR_OP_MUL_FACTORS = 3;
const FR_VECTOR_OP_BIT_REVERSE_COPY = 4;

const ELEMENT_BYTES = 32;
const UNIFORM_BYTES = 32;

const CONFIGS: Record<string, VectorConfig> = {
  bn254: {
    curve: "bn254",
    title: "BN254 fr Vector Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bn254_fr_vector_ops.json",
    arithShaderPath: "/shaders/curves/bn254/fr_arith.wgsl",
    vectorShaderPath: "/shaders/curves/bn254/fr_vector.wgsl",
    arithLabel: "bn254-fr",
    vectorLabel: "bn254-fr-vector",
  },
  bls12_377: {
    curve: "bls12_377",
    title: "BLS12-377 fr Vector Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bls12_377_fr_vector_ops.json",
    arithShaderPath: "/shaders/curves/bls12_377/fr_arith.wgsl",
    vectorShaderPath: "/shaders/curves/bls12_377/fr_vector.wgsl",
    arithLabel: "bls12-377-fr",
    vectorLabel: "bls12-377-fr-vector",
  },
  bls12_381: {
    curve: "bls12_381",
    title: "BLS12-381 fr Vector Ops Browser Smoke",
    vectorPath: "/tests/fixtures/api/vectors/fr/bls12_381_fr_vector_ops.json",
    arithShaderPath: "/shaders/curves/bls12_381/fr_arith.wgsl",
    vectorShaderPath: "/shaders/curves/bls12_381/fr_vector.wgsl",
    arithLabel: "bls12-381-fr",
    vectorLabel: "bls12-381-fr-vector",
  },
};

function packHexBatch(hexValues: readonly string[]): Uint8Array {
  const out = new Uint8Array(hexValues.length * ELEMENT_BYTES);
  hexValues.forEach((hex, index) => {
    out.set(hexToBytes(hex), index * ELEMENT_BYTES);
  });
  return out;
}

function createStorageBuffer(device: GPUDevice, label: string, size: number, usage: GPUBufferUsageFlags): GPUBuffer {
  return device.createBuffer({ label, size, usage });
}

function createKernel(device: GPUDevice, label: string, shaderCode: string, entryPoint: string): {
  pipeline: GPUComputePipeline;
  bindGroupLayout: GPUBindGroupLayout;
} {
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

async function runKernel(
  device: GPUDevice,
  kernel: { pipeline: GPUComputePipeline; bindGroupLayout: GPUBindGroupLayout },
  aHex: readonly string[],
  bHex: readonly string[],
  opcode: number,
  logCount: number,
): Promise<string[]> {
  const count = aHex.length;
  const dataBytes = count * ELEMENT_BYTES;
  const inputA = createStorageBuffer(device, "input-a", dataBytes, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST);
  const inputB = createStorageBuffer(device, "input-b", dataBytes, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST);
  const output = createStorageBuffer(device, "output", dataBytes, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC);
  const staging = createStorageBuffer(device, "staging", dataBytes, GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ);
  const uniform = device.createBuffer({
    label: "params",
    size: UNIFORM_BYTES,
    usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
  });

  const aBytes = packHexBatch(aHex);
  const bBytes = packHexBatch(bHex);
  device.queue.writeBuffer(inputA, 0, aBytes.buffer.slice(aBytes.byteOffset, aBytes.byteOffset + aBytes.byteLength));
  device.queue.writeBuffer(inputB, 0, bBytes.buffer.slice(bBytes.byteOffset, bBytes.byteOffset + bBytes.byteLength));
  const params = new Uint32Array(UNIFORM_BYTES / 4);
  params[0] = count;
  params[1] = opcode;
  params[2] = logCount;
  device.queue.writeBuffer(uniform, 0, params.buffer);

  const bindGroup = device.createBindGroup({
    label: "bind-group",
    layout: kernel.bindGroupLayout,
    entries: [
      { binding: 0, resource: { buffer: inputA } },
      { binding: 1, resource: { buffer: inputB } },
      { binding: 2, resource: { buffer: output } },
      { binding: 3, resource: { buffer: uniform } },
    ],
  });

  const encoder = device.createCommandEncoder({ label: "encoder" });
  const pass = encoder.beginComputePass({ label: "pass" });
  pass.setPipeline(kernel.pipeline);
  pass.setBindGroup(0, bindGroup);
  pass.dispatchWorkgroups(Math.ceil(count / 64));
  pass.end();
  encoder.copyBufferToBuffer(output, 0, staging, 0, dataBytes);
  device.queue.submit([encoder.finish()]);

  await staging.mapAsync(GPUMapMode.READ);
  const view = new Uint8Array(staging.getMappedRange()).slice();
  staging.unmap();

  inputA.destroy();
  inputB.destroy();
  output.destroy();
  staging.destroy();
  uniform.destroy();

  const out: string[] = [];
  for (let i = 0; i < count; i += 1) {
    out.push(bytesToHex(view.slice(i * ELEMENT_BYTES, (i + 1) * ELEMENT_BYTES)));
  }
  return out;
}

function expectBatch(name: string, got: readonly string[], want: readonly string[]): void {
  if (got.length !== want.length) {
    throw new Error(`${name}: length mismatch got=${got.length} want=${want.length}`);
  }
  for (let i = 0; i < got.length; i += 1) {
    if (got[i] !== want[i]) {
      throw new Error(`${name}: mismatch at index ${i}: got=${got[i]} want=${want[i]}`);
    }
  }
}

export async function runSuite(module: CurveModule, log: (msg: string) => void): Promise<{ passed: number; failed: number }> {
  const config = CONFIGS[module.id];
  const device = module.context.device;
  log(`=== ${config.title} ===`);
  log("");

  const [arithShader, vectorShader] = await Promise.all([
    fetchText(config.arithShaderPath),
    fetchText(config.vectorShaderPath),
  ]);
  const vectorsText = await fetchText(config.vectorPath);
  const vectors = JSON.parse(vectorsText) as FRVectorOpsVectors;
  log(`cases.vector = ${vectors.vector_cases.length}`);

  const arithKernel = createKernel(device, config.arithLabel, arithShader, "fr_ops_main");
  const vectorKernel = createKernel(device, config.vectorLabel, vectorShader, "fr_vector_main");

  for (const vectorCase of vectors.vector_cases) {
    const zeros = vectorCase.mont_inputs_le.map(() => "0000000000000000000000000000000000000000000000000000000000000000");
    expectBatch(`${vectorCase.name}:add`, await runKernel(device, arithKernel, vectorCase.mont_inputs_le, vectorCase.mont_factors_le, FR_OP_ADD, 0), vectorCase.add_expected_le);
    expectBatch(`${vectorCase.name}:sub`, await runKernel(device, arithKernel, vectorCase.mont_inputs_le, vectorCase.mont_factors_le, FR_OP_SUB, 0), vectorCase.sub_expected_le);
    expectBatch(`${vectorCase.name}:mul`, await runKernel(device, arithKernel, vectorCase.mont_inputs_le, vectorCase.mont_factors_le, FR_OP_MUL, 0), vectorCase.mul_expected_le);
    expectBatch(`${vectorCase.name}:to_mont`, await runKernel(device, arithKernel, vectorCase.regular_inputs_le, zeros, FR_OP_TO_MONT, 0), vectorCase.to_mont_expected_le);
    expectBatch(`${vectorCase.name}:from_mont`, await runKernel(device, arithKernel, vectorCase.mont_inputs_le, zeros, FR_OP_FROM_MONT, 0), vectorCase.from_mont_expected_le);
    expectBatch(`${vectorCase.name}:mul_factors`, await runKernel(device, vectorKernel, vectorCase.mont_inputs_le, vectorCase.mont_factors_le, FR_VECTOR_OP_MUL_FACTORS, 0), vectorCase.mul_expected_le);
    const logCount = Math.round(Math.log2(vectorCase.mont_inputs_le.length));
    expectBatch(`${vectorCase.name}:bit_reverse_copy`, await runKernel(device, vectorKernel, vectorCase.mont_inputs_le, zeros, FR_VECTOR_OP_BIT_REVERSE_COPY, logCount), vectorCase.bit_reverse_expected_le);
  }

  log("add: OK");
  log("sub: OK");
  log("mul: OK");
  log("to_mont: OK");
  log("from_mont: OK");
  log("mul_factors: OK");
  log("bit_reverse_copy: OK");
  log("");
  log(`PASS: ${config.title} succeeded`);
  return { passed: 1, failed: 0 };
}
