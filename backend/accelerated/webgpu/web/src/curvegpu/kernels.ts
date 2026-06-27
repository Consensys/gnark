import type { CurveID, FieldID, FieldShape } from "./types.js";
import { shapeFor } from "./types.js";
import { fetchShaderText } from "./shaders.js";

export interface KernelDescriptor {
  curve: CurveID;
  field: FieldID;
  shaderPath: string;
  shape: FieldShape;
}

export async function loadFieldKernel(curve: CurveID, field: FieldID): Promise<KernelDescriptor> {
  const shaderPath = `/shaders/curves/${curve}/${field}_arith.wgsl`;
  await fetchShaderText(shaderPath);
  return {
    curve,
    field,
    shaderPath,
    shape: shapeFor(curve, field),
  };
}
