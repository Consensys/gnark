import type { Kernel } from "./msm_gpu_runtime.js";
import type { SimpleKernel } from "./runtime_common.js";
import { loadShaderParts } from "./runtime_common.js";

declare const GPUShaderStage: { COMPUTE: number };

export interface PipelineRegistry {
  getOpsKernel(entryPoint: string): SimpleKernel;
  getMSMKernel(entryPoint: string): Kernel;
}

export type OpsShaderSpec = {
  shaderParts: readonly string[];
  entryPoint: string;
  /** Pass WORKGROUP_SIZE override constant at pipeline creation time. Only valid for shaders that declare `override WORKGROUP_SIZE`. */
  useWorkgroupOverride?: boolean;
};

export type MSMShaderSpec = {
  shaderParts: readonly string[];
  entryPoints: readonly string[];
};

export async function buildPipelineRegistry(options: {
  device: GPUDevice;
  opsShaders: OpsShaderSpec[];
  msmShaders: MSMShaderSpec[];
  /** Workgroup size to use for ops kernels that declare `override WORKGROUP_SIZE`. Defaults to 64. */
  opsWorkgroupSize?: number;
  debug?: boolean;
}): Promise<PipelineRegistry> {
  const { device, opsShaders, msmShaders, opsWorkgroupSize = 64, debug = false } = options;

  // Shared bind group layout for ops kernels (4-binding: read-only-storage×2, storage, uniform)
  const opsLayout = device.createBindGroupLayout({
    label: "curvegpu-ops-bgl",
    entries: [
      { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
      { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: "uniform" } },
    ],
  });

  // Shared bind group layout for MSM kernels (7-binding: same 4 + read-only-storage×3)
  const msmLayout = device.createBindGroupLayout({
    label: "curvegpu-msm-bgl",
    entries: [
      { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
      { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: "uniform" } },
      { binding: 4, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 5, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 6, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
    ],
  });

  const opsPipelineLayout = device.createPipelineLayout({
    label: "curvegpu-ops-pl",
    bindGroupLayouts: [opsLayout],
  });

  const msmPipelineLayout = device.createPipelineLayout({
    label: "curvegpu-msm-pl",
    bindGroupLayouts: [msmLayout],
  });

  // Load all shader texts in parallel
  const [opsShaderTexts, msmShaderTexts] = await Promise.all([
    Promise.all(opsShaders.map((spec) => loadShaderParts(spec.shaderParts))),
    Promise.all(msmShaders.map((spec) => loadShaderParts(spec.shaderParts))),
  ]);

  const opsKernels = new Map<string, SimpleKernel>();
  const msmKernels = new Map<string, Kernel>();

  // Create all pipelines in parallel
  await Promise.all([
    ...opsShaders.map(async (spec, i) => {
      const shaderCode = opsShaderTexts[i];
      const shaderModule = device.createShaderModule({
        label: `curvegpu-ops-${spec.entryPoint}-shader`,
        code: shaderCode,
      });
      if (debug) {
        console.debug(`[curvegpu] createComputePipelineAsync: ${spec.entryPoint}`);
      }
      const effectiveWorkgroupSize = spec.useWorkgroupOverride ? opsWorkgroupSize : 64;
      const computeDesc: GPUProgrammableStage = spec.useWorkgroupOverride
        ? { module: shaderModule, entryPoint: spec.entryPoint, constants: { WORKGROUP_SIZE: effectiveWorkgroupSize } }
        : { module: shaderModule, entryPoint: spec.entryPoint };
      const pipeline = await device.createComputePipelineAsync({
        label: `curvegpu-ops-${spec.entryPoint}`,
        layout: opsPipelineLayout,
        compute: computeDesc,
      });
      opsKernels.set(spec.entryPoint, { pipeline, bindGroupLayout: opsLayout, workgroupSize: effectiveWorkgroupSize });
    }),
    ...msmShaders.map(async (spec, i) => {
      const shaderCode = msmShaderTexts[i];
      const shaderModule = device.createShaderModule({
        label: `curvegpu-msm-${spec.entryPoints[0]}-shader`,
        code: shaderCode,
      });
      await Promise.all(
        spec.entryPoints.map(async (entryPoint) => {
          if (debug) {
            console.debug(`[curvegpu] createComputePipelineAsync: ${entryPoint}`);
          }
          const pipeline = await device.createComputePipelineAsync({
            label: `curvegpu-msm-${entryPoint}`,
            layout: msmPipelineLayout,
            compute: { module: shaderModule, entryPoint },
          });
          msmKernels.set(entryPoint, { pipeline, bindGroupLayout: msmLayout });
        }),
      );
    }),
  ]);

  return {
    getOpsKernel(entryPoint: string): SimpleKernel {
      const kernel = opsKernels.get(entryPoint);
      if (!kernel) {
        throw new Error(`[curvegpu] ops kernel not found: ${entryPoint}`);
      }
      return kernel;
    },
    getMSMKernel(entryPoint: string): Kernel {
      const kernel = msmKernels.get(entryPoint);
      if (!kernel) {
        throw new Error(`[curvegpu] MSM kernel not found: ${entryPoint}`);
      }
      return kernel;
    },
  };
}
