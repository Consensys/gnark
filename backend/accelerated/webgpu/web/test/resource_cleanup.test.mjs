import assert from "node:assert/strict";
import test from "node:test";

globalThis.GPUBufferUsage = {
  STORAGE: 1,
  COPY_DST: 2,
  COPY_SRC: 4,
  MAP_READ: 8,
  UNIFORM: 16,
};
globalThis.GPUMapMode = { READ: 1 };

const {
  buildJacPippengerRuntime,
  runSparseSignedPippengerMSM,
} = await import("../dist/src/curvegpu/msm_pippenger.js");
const { readbackBuffer } = await import("../dist/src/curvegpu/msm_gpu_runtime.js");
const { createCurveGPUContext } = await import("../dist/src/curvegpu/context.js");

function createFakeDevice(failOnCompletion = Number.POSITIVE_INFINITY, failMap = false) {
  const buffers = [];
  let completions = 0;
  let destroyCalls = 0;

  const device = {
    buffers,
    limits: { maxComputeWorkgroupSizeX: 256 },
    lost: new Promise(() => {}),
    queue: {
      writeBuffer() {},
      submit() {},
      onSubmittedWorkDone() {
        completions += 1;
        if (completions === failOnCompletion) {
          return Promise.reject(new Error("forced GPU failure"));
        }
        return Promise.resolve();
      },
    },
    createBuffer(descriptor) {
      const buffer = {
        descriptor,
        destroyed: false,
        mapped: false,
        pooled: false,
        destroy() {
          this.destroyed = true;
        },
        mapAsync() {
          if (failMap) {
            return Promise.reject(new Error("forced map failure"));
          }
          this.mapped = true;
          return Promise.resolve();
        },
        getMappedRange() {
          return new ArrayBuffer(descriptor.size);
        },
        unmap() {
          this.mapped = false;
        },
      };
      buffers.push(buffer);
      return buffer;
    },
    createBindGroup() {
      return {};
    },
    createCommandEncoder() {
      return {
        beginComputePass() {
          return {
            setPipeline() {},
            setBindGroup() {},
            dispatchWorkgroups() {},
            end() {},
          };
        },
        copyBufferToBuffer() {},
        finish() {
          return {};
        },
      };
    },
    destroy() {
      destroyCalls += 1;
    },
    get destroyCalls() {
      return destroyCalls;
    },
  };
  return device;
}

function createFakePool(device) {
  const acquired = [];
  const released = [];
  return {
    acquired,
    released,
    acquire(size, usage, label) {
      const buffer = device.createBuffer({ size, usage, label });
      buffer.pooled = true;
      acquired.push(buffer);
      return buffer;
    },
    release(buffer) {
      released.push(buffer);
    },
  };
}

function fakeKernel() {
  return { pipeline: {}, bindGroupLayout: {} };
}

test("sparse Pippenger releases every buffer when the first dispatch fails", async () => {
  const device = createFakeDevice(1);
  const pool = createFakePool(device);
  const runtime = {
    bucket: fakeKernel(),
    combine: fakeKernel(),
    async reduceWindows() {
      throw new Error("unexpected window reduction");
    },
  };

  await assert.rejects(
    runSparseSignedPippengerMSM({
      device,
      pool,
      runtime,
      basesBytes: new Uint8Array(12),
      pointBytes: 12,
      uniformBytes: 32,
      zeroPointBytes: new Uint8Array(12),
      scalarWords: new Uint32Array(8),
      count: 1,
      termsPerInstance: 1,
      window: 4,
      labelPrefix: "test-msm",
    }),
    /forced GPU failure/,
  );

  assert.equal(pool.released.length, pool.acquired.length);
  assert.deepEqual(new Set(pool.released), new Set(pool.acquired));
  const owned = device.buffers.filter((buffer) => !buffer.pooled);
  assert.ok(owned.length > 0);
  assert.ok(owned.every((buffer) => buffer.destroyed));
});

test("sparse Pippenger releases every buffer after a successful run", async () => {
  const device = createFakeDevice();
  const pool = createFakePool(device);
  const runtime = buildJacPippengerRuntime({
    bucket: fakeKernel(),
    weightJac: fakeKernel(),
    subsumJac: fakeKernel(),
    combine: fakeKernel(),
  });

  const result = await runSparseSignedPippengerMSM({
    device,
    pool,
    runtime,
    basesBytes: new Uint8Array(12),
    pointBytes: 12,
    uniformBytes: 32,
    zeroPointBytes: new Uint8Array(12),
    scalarWords: new Uint32Array(8),
    count: 1,
    termsPerInstance: 1,
    window: 4,
    labelPrefix: "test-msm-success",
  });

  assert.equal(result.byteLength, 12);
  assert.equal(pool.released.length, pool.acquired.length);
  assert.deepEqual(new Set(pool.released), new Set(pool.acquired));
  const owned = device.buffers.filter((buffer) => !buffer.pooled);
  assert.ok(owned.length > 0);
  assert.ok(owned.every((buffer) => buffer.destroyed));
});

test("window reduction cleans intermediate buffers when its second dispatch fails", async () => {
  const device = createFakeDevice(2);
  const pool = createFakePool(device);
  const runtime = buildJacPippengerRuntime({
    bucket: fakeKernel(),
    weightJac: fakeKernel(),
    subsumJac: fakeKernel(),
    combine: fakeKernel(),
  });
  const input = { destroy() {} };

  await assert.rejects(
    runtime.reduceWindows({
      device,
      pool,
      pointBytes: 12,
      uniformBytes: 32,
      zeroInput: input,
      bucketOutput: input,
      bucketCountOut: 1,
      bucketValuesInput: input,
      windowStartsInput: input,
      windowCountsInput: input,
      metadata: { numWindows: 2 },
      count: 1,
      labelPrefix: "test-window",
    }),
    /forced GPU failure/,
  );

  assert.equal(pool.acquired.length, 1);
  assert.deepEqual(pool.released, pool.acquired);
  const owned = device.buffers.filter((buffer) => !buffer.pooled);
  assert.ok(owned.length > 0);
  assert.ok(owned.every((buffer) => buffer.destroyed));
});

test("readback destroys its staging buffer when mapping fails", async () => {
  const device = createFakeDevice(Number.POSITIVE_INFINITY, true);
  const source = { destroy() {} };

  await assert.rejects(readbackBuffer(device, source, 16), /forced map failure/);

  assert.equal(device.buffers.length, 1);
  assert.equal(device.buffers[0].destroyed, true);
});

test("closing a context destroys the device and closes its buffer pool once", async () => {
  const device = createFakeDevice();
  const adapter = {
    limits: {},
    async requestDevice() {
      return device;
    },
  };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      gpu: {
        async requestAdapter() {
          return adapter;
        },
      },
    },
  });

  const context = await createCurveGPUContext({ requireAdapterLimits: false });
  const cached = context.bufferPool.acquire(8, globalThis.GPUBufferUsage.STORAGE);
  context.bufferPool.release(cached);
  const checkedOut = context.bufferPool.acquire(32, globalThis.GPUBufferUsage.STORAGE);

  context.close();
  context.close();
  context.bufferPool.release(checkedOut);

  assert.equal(device.destroyCalls, 1);
  assert.equal(cached.destroyed, true);
  assert.equal(checkedOut.destroyed, true);
  assert.throws(
    () => context.bufferPool.acquire(4, globalThis.GPUBufferUsage.STORAGE),
    /buffer pool is closed/,
  );
});
