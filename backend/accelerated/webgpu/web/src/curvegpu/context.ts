import { getAdapterInfo } from "./browser_utils.js";
import type {
  CurveGPUAdapterDiagnostics,
  CurveGPUContext,
  CurveGPUContextOptions,
  CurveGPURequestedLimits,
} from "./api.js";
import { BufferPool } from "./buffer_pool.js";
import { CurveGPUNotSupportedError } from "./errors.js";

type AdapterWithLimits = GPUAdapter & {
  isFallbackAdapter?: boolean;
  limits?: {
    maxStorageBufferBindingSize?: number;
    maxBufferSize?: number;
  };
};

function collectRequestedLimits(adapter: AdapterWithLimits, options: CurveGPUContextOptions): CurveGPURequestedLimits {
  const requestedLimits: CurveGPURequestedLimits = {};
  if (options.requireAdapterLimits !== false) {
    if (adapter.limits?.maxStorageBufferBindingSize !== undefined) {
      requestedLimits.maxStorageBufferBindingSize = adapter.limits.maxStorageBufferBindingSize;
    }
    if (adapter.limits?.maxBufferSize !== undefined) {
      requestedLimits.maxBufferSize = adapter.limits.maxBufferSize;
    }
  }
  if (options.requiredLimits?.maxStorageBufferBindingSize !== undefined) {
    requestedLimits.maxStorageBufferBindingSize = options.requiredLimits.maxStorageBufferBindingSize;
  }
  if (options.requiredLimits?.maxBufferSize !== undefined) {
    requestedLimits.maxBufferSize = options.requiredLimits.maxBufferSize;
  }
  return requestedLimits;
}

function buildDiagnostics(adapter: AdapterWithLimits, adapterInfo: GPUAdapterInfo | null): CurveGPUAdapterDiagnostics {
  return {
    vendor: adapterInfo?.vendor || undefined,
    architecture: adapterInfo?.architecture || undefined,
    description: adapterInfo?.description || undefined,
    isFallbackAdapter: adapter.isFallbackAdapter,
  };
}

/**
 * Create the shared browser WebGPU context for the library.
 *
 * The context owns adapter and device acquisition. It is intended to be
 * created once and reused across field, group, NTT, and MSM operations.
 */
export async function createCurveGPUContext(options: CurveGPUContextOptions = {}): Promise<CurveGPUContext> {
  if (!navigator.gpu) {
    throw new CurveGPUNotSupportedError(
      "WebGPU is not supported in this browser. " +
      "WebGPU requires Chrome 113+, Edge 113+, or Safari 18+. " +
      "Firefox requires the dom.webgpu.enabled flag.",
    );
  }

  const adapter = (await navigator.gpu.requestAdapter({
    powerPreference: options.powerPreference,
  })) as AdapterWithLimits | null;
  if (!adapter) {
    throw new CurveGPUNotSupportedError(
      "requestAdapter returned null. " +
      "This can happen when no suitable GPU is available, " +
      "when the browser is running in a context without GPU access, " +
      "or when hardware acceleration is disabled in browser settings.",
    );
  }

  const adapterInfo = await getAdapterInfo(adapter);
  const requestedLimits = collectRequestedLimits(adapter, options);
  const device = await adapter.requestDevice({
    requiredLimits: Object.keys(requestedLimits).length > 0 ? requestedLimits : undefined,
  });

  const debug = options.debug ?? false;
  const maxWorkgroupSize = (device.limits as { maxComputeWorkgroupSizeX?: number }).maxComputeWorkgroupSizeX ?? 256;
  const bufferPool = new BufferPool(device);
  let closed = false;

  const deviceLost: Promise<GPUDeviceLostInfo> = device.lost.then((info) => {
    if (debug) {
      console.debug(`[curvegpu] device lost: reason=${info.reason} message=${info.message}`);
    }
    return info;
  });

  return {
    adapter,
    device,
    adapterInfo,
    diagnostics: buildDiagnostics(adapter, adapterInfo),
    requestedLimits,
    debug,
    maxWorkgroupSize,
    bufferPool,
    deviceLost,
    close(): void {
      if (closed) {
        return;
      }
      closed = true;
      bufferPool.destroy();
    },
  };
}
