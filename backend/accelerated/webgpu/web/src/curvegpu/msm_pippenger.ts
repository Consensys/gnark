import { buildSparseSignedBucketMetadataWords } from "./msm_shared.js";
import {
  createBindGroupForBuffers,
  createEmptyPointStorageBuffer,
  createParamsBuffer,
  createStorageBufferFromBytes,
  createU32StorageBuffer,
  type Kernel,
  readbackBuffer,
  submitKernel,
} from "./msm_gpu_runtime.js";
import type { BufferPool } from "./buffer_pool.js";

declare const GPUBufferUsage: { STORAGE: number; COPY_SRC: number; COPY_DST: number };

type SparseSignedBucketMetadata = ReturnType<typeof buildSparseSignedBucketMetadataWords>;

export type WindowReductionOptions = {
  device: GPUDevice;
  pool?: BufferPool;
  pointBytes: number;
  uniformBytes: number;
  zeroInput: GPUBuffer;
  bucketOutput: GPUBuffer;
  bucketCountOut: number;
  bucketValuesInput: GPUBuffer;
  windowStartsInput: GPUBuffer;
  windowCountsInput: GPUBuffer;
  metadata: SparseSignedBucketMetadata;
  count: number;
  labelPrefix: string;
};

export type WindowReductionResult = {
  windowOutput: GPUBuffer;
  cleanupBuffers: GPUBuffer[];
};

export type PippengerRuntime = {
  bucket: Kernel;
  bucketWorkgroupSize?: number;
  combine: Kernel;
  reduceWindows(options: WindowReductionOptions): Promise<WindowReductionResult>;
};

export function buildJacPippengerRuntime(
  kernels: { bucket: Kernel; weightJac: Kernel; subsumJac: Kernel; combine: Kernel },
  workgroupSize = 64,
  debug = false,
): PippengerRuntime {
  return {
    bucket: kernels.bucket,
    bucketWorkgroupSize: workgroupSize,
    combine: kernels.combine,
    async reduceWindows(options: WindowReductionOptions): Promise<WindowReductionResult> {
      const {
        device,
        pool,
        pointBytes,
        uniformBytes,
        zeroInput,
        bucketOutput,
        bucketCountOut,
        bucketValuesInput,
        windowStartsInput,
        windowCountsInput,
        metadata,
        count,
        labelPrefix,
      } = options;
      const cleanupBuffers: GPUBuffer[] = [];
      let windowOutput: GPUBuffer | undefined;
      let succeeded = false;
      try {
        const weightedBucketOutput = createEmptyPointStorageBuffer(device, `${labelPrefix}-weighted-out`, bucketCountOut, pointBytes);
        cleanupBuffers.push(weightedBucketOutput);
        const weightParams = createParamsBuffer(device, `${labelPrefix}-weight-params`, uniformBytes, { count: bucketCountOut });
        cleanupBuffers.push(weightParams);
        const weightBindGroup = createBindGroupForBuffers(device, kernels.weightJac, `${labelPrefix}-weight-bg`,
          bucketOutput, zeroInput, weightedBucketOutput, weightParams, bucketValuesInput);
        await submitKernel(device, kernels.weightJac, weightBindGroup, bucketCountOut, `${labelPrefix}-weight`, workgroupSize, debug);

        const windowSize = Math.max(1, count * metadata.numWindows) * pointBytes;
        const windowUsage = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST;
        windowOutput = pool
          ? pool.acquire(windowSize, windowUsage, `${labelPrefix}-window-out`)
          : createEmptyPointStorageBuffer(device, `${labelPrefix}-window-out`, count * metadata.numWindows, pointBytes);

        const windowParams = createParamsBuffer(device, `${labelPrefix}-window-params`, uniformBytes, { count: count * metadata.numWindows });
        cleanupBuffers.push(windowParams);
        const windowBindGroup = createBindGroupForBuffers(device, kernels.subsumJac, `${labelPrefix}-window-bg`,
          weightedBucketOutput, zeroInput, windowOutput, windowParams, bucketValuesInput, windowStartsInput, windowCountsInput);
        await submitKernel(device, kernels.subsumJac, windowBindGroup, count * metadata.numWindows * workgroupSize,
          `${labelPrefix}-window`, workgroupSize, debug);
        succeeded = true;
        return { windowOutput, cleanupBuffers };
      } finally {
        if (!succeeded) {
          if (windowOutput) {
            if (pool) {
              pool.release(windowOutput);
            } else {
              windowOutput.destroy();
            }
          }
          for (let i = cleanupBuffers.length - 1; i >= 0; i -= 1) {
            cleanupBuffers[i].destroy();
          }
        }
      }
    },
  };
}

export async function runSparseSignedPippengerMSM(options: {
  device: GPUDevice;
  pool?: BufferPool;
  runtime: PippengerRuntime;
  basesBytes: Uint8Array;
  pointBytes: number;
  uniformBytes: number;
  zeroPointBytes: Uint8Array;
  scalarWords: Uint32Array;
  count: number;
  termsPerInstance: number;
  window: number;
  maxChunkSize?: number;
  labelPrefix: string;
  debug?: boolean;
}): Promise<Uint8Array> {
  const {
    device,
    pool,
    runtime,
    basesBytes,
    pointBytes,
    uniformBytes,
    zeroPointBytes,
    scalarWords,
    count,
    termsPerInstance,
    window,
    maxChunkSize = 256,
    labelPrefix,
    debug = false,
  } = options;

  const metadata = buildSparseSignedBucketMetadataWords(scalarWords, count, termsPerInstance, window, maxChunkSize);
  if (debug) {
    console.debug("[curvegpu] msm metadata", {
    labelPrefix,
    count,
    termsPerInstance,
    window,
    pointBytes,
    numWindows: metadata.numWindows,
    bucketCount: metadata.bucketCount,
    bucketCountOut: metadata.bucketPointers.length,
    baseIndicesLen: metadata.baseIndices.length,
    bucketPointersLen: metadata.bucketPointers.length,
    bucketSizesLen: metadata.bucketSizes.length,
    bucketValuesLen: metadata.bucketValues.length,
    windowStartsLen: metadata.windowStarts.length,
    windowCountsLen: metadata.windowCounts.length,
    bucketSizesHead: Array.from(metadata.bucketSizes.slice(0, 16)),
    bucketValuesHead: Array.from(metadata.bucketValues.slice(0, 16)),
    windowCountsHead: Array.from(metadata.windowCounts.slice(0, 16)),
    });
  }
  const storageInUsage = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST;
  const storagePointUsage = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST;
  const pooledBuffers: GPUBuffer[] = [];
  const ownedBuffers: GPUBuffer[] = [];
  const trackPooled = (buffer: GPUBuffer): GPUBuffer => {
    pooledBuffers.push(buffer);
    return buffer;
  };
  const trackOwned = (buffer: GPUBuffer): GPUBuffer => {
    ownedBuffers.push(buffer);
    return buffer;
  };

  try {
    const zeroSize = Math.max(4, pointBytes);
    const zeroInput = pool
      ? trackPooled(pool.acquire(zeroSize, storageInUsage, `${labelPrefix}-zero`))
      : trackOwned(createStorageBufferFromBytes(device, `${labelPrefix}-zero`, zeroPointBytes, pointBytes));
    if (pool) {
      device.queue.writeBuffer(zeroInput, 0, zeroPointBytes.buffer, zeroPointBytes.byteOffset, zeroPointBytes.byteLength);
    }

    const basesSize = Math.max(1, termsPerInstance * count) * pointBytes;
    const basesInput = pool
      ? trackPooled(pool.acquire(basesSize, storageInUsage, `${labelPrefix}-bases`))
      : trackOwned(createStorageBufferFromBytes(device, `${labelPrefix}-bases`, basesBytes, basesSize));
    if (pool) {
      device.queue.writeBuffer(basesInput, 0, basesBytes.buffer, basesBytes.byteOffset, basesBytes.byteLength);
    }
    const baseIndicesInput = trackOwned(createU32StorageBuffer(device, `${labelPrefix}-base-indices`, metadata.baseIndices));
    const bucketPointersInput = trackOwned(createU32StorageBuffer(device, `${labelPrefix}-bucket-pointers`, metadata.bucketPointers));
    const bucketSizesInput = trackOwned(createU32StorageBuffer(device, `${labelPrefix}-bucket-sizes`, metadata.bucketSizes));

    const bucketCountOut = metadata.bucketPointers.length;
    const bucketSize = Math.max(1, bucketCountOut) * pointBytes;
    const bucketOutput = pool
      ? trackPooled(pool.acquire(bucketSize, storagePointUsage, `${labelPrefix}-bucket-out`))
      : trackOwned(createEmptyPointStorageBuffer(device, `${labelPrefix}-bucket-out`, bucketCountOut, pointBytes));
    const bucketParams = trackOwned(createParamsBuffer(device, `${labelPrefix}-bucket-params`, uniformBytes, {
      count: bucketCountOut,
      termsPerInstance,
      window,
      numWindows: metadata.numWindows,
      bucketCount: metadata.bucketCount,
    }));
    const bucketBindGroup = createBindGroupForBuffers(
      device,
      runtime.bucket,
      `${labelPrefix}-bucket-bg`,
      basesInput,
      zeroInput,
      bucketOutput,
      bucketParams,
      baseIndicesInput,
      bucketPointersInput,
      bucketSizesInput,
    );
    await submitKernel(device, runtime.bucket, bucketBindGroup, bucketCountOut, `${labelPrefix}-bucket`, runtime.bucketWorkgroupSize ?? 64, debug);

    const bucketValuesInput = trackOwned(createU32StorageBuffer(device, `${labelPrefix}-bucket-values`, metadata.bucketValues));
    const windowStartsInput = trackOwned(createU32StorageBuffer(device, `${labelPrefix}-window-starts`, metadata.windowStarts));
    const windowCountsInput = trackOwned(createU32StorageBuffer(device, `${labelPrefix}-window-counts`, metadata.windowCounts));

    const { windowOutput, cleanupBuffers: windowReductionCleanup } = await runtime.reduceWindows({
      device,
      pool,
      pointBytes,
      uniformBytes,
      zeroInput,
      bucketOutput,
      bucketCountOut,
      bucketValuesInput,
      windowStartsInput,
      windowCountsInput,
      metadata,
      count,
      labelPrefix,
    });
    if (pool) {
      trackPooled(windowOutput);
    } else {
      trackOwned(windowOutput);
    }
    windowReductionCleanup.forEach(trackOwned);

    const finalSize = Math.max(1, count) * pointBytes;
    const finalOutput = pool
      ? trackPooled(pool.acquire(finalSize, storagePointUsage, `${labelPrefix}-final-out`))
      : trackOwned(createEmptyPointStorageBuffer(device, `${labelPrefix}-final-out`, count, pointBytes));
    const finalParams = trackOwned(createParamsBuffer(device, `${labelPrefix}-final-params`, uniformBytes, {
      count,
      termsPerInstance,
      window,
      numWindows: metadata.numWindows,
      bucketCount: metadata.bucketCount,
    }));
    const finalBindGroup = createBindGroupForBuffers(
      device,
      runtime.combine,
      `${labelPrefix}-final-bg`,
      windowOutput,
      zeroInput,
      finalOutput,
      finalParams,
    );
    await submitKernel(device, runtime.combine, finalBindGroup, count, `${labelPrefix}-final`, 64, debug);

    return await readbackBuffer(device, finalOutput, Math.max(1, count) * pointBytes);
  } finally {
    if (pool) {
      for (let i = pooledBuffers.length - 1; i >= 0; i -= 1) {
        pool.release(pooledBuffers[i]);
      }
    }
    for (let i = ownedBuffers.length - 1; i >= 0; i -= 1) {
      ownedBuffers[i].destroy();
    }
  }
}
