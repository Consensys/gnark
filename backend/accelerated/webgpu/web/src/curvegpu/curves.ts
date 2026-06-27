import type { CurveModule, CurveGPUContext, SupportedCurveID } from "./api.js";
import { createFieldModule } from "./field_module.js";
import { createG1Module } from "./g1_module.js";
import { createG2Module } from "./g2_module.js";
import { createG2MSMModule } from "./g2_msm_module.js";
import { createGroth16Module } from "./groth16_module.js";
import { createPlonkModule } from "./plonk_module.js";
import { createPlonkQuotientModule } from "./plonk_quotient_module.js";
import { createG1MSMModule } from "./msm_module.js";
import { buildJacPippengerRuntime } from "./msm_pippenger.js";
import { createNTTModule } from "./ntt_module.js";
import { buildPipelineRegistry } from "./pipeline_registry.js";
import { shapeFor } from "./types.js";

/**
 * Runtime metadata for a supported curve.
 *
 * This is kept separate from the page harnesses so the library can evolve
 * around one shared source of curve-specific facts.
 */
export interface CurveDefinition {
  readonly id: SupportedCurveID;
  readonly frArithShaderPath: string;
  readonly frVectorShaderPath: string;
  readonly frNTTShaderPath: string;
  readonly frNTTDomainPath?: string;
  readonly frModulusHex?: string;
  readonly fpArithShaderPath: string;
  readonly g1ArithShaderParts: readonly string[];
  readonly g1MSMShaderParts: readonly string[];
  readonly g2ArithShaderParts: readonly string[];
  readonly g2MSMShaderParts: readonly string[];
  readonly coordinateBytes: number;
  readonly pointBytes: number;
  readonly g2CoordinateBytes: number;
  readonly g2PointBytes: number;
  readonly zeroHex: string;
}

function g1OpsShaderParts(fpArithShaderPath: string, g1IOPath: string): readonly string[] {
  return [
    `${fpArithShaderPath}#section=fp-types`,
    `${fpArithShaderPath}#section=fp-consts`,
    `${fpArithShaderPath}#section=fp-core`,
    "/shaders/common/g1_core.wgsl",
    "/shaders/common/g1_ops_bindings.wgsl",
    g1IOPath,
    "/shaders/common/g1_ops_main.wgsl",
  ];
}

function g1MSMShaderParts(fpArithShaderPath: string, g1IOPath: string): readonly string[] {
  return [
    `${fpArithShaderPath}#section=fp-types`,
    `${fpArithShaderPath}#section=fp-consts`,
    `${fpArithShaderPath}#section=fp-core`,
    "/shaders/common/g1_core.wgsl",
    "/shaders/common/g1_msm_bindings.wgsl",
    g1IOPath,
    "/shaders/common/g1_msm_jac.wgsl",
  ];
}

function g2OpsShaderParts(fpArithShaderPath: string, g2ArithPath: string, g2IOPath: string): readonly string[] {
  return [
    `${fpArithShaderPath}#section=fp-types`,
    `${fpArithShaderPath}#section=fp-consts`,
    `${fpArithShaderPath}#section=fp-core`,
    "/shaders/common/g2_ops_bindings.wgsl",
    g2ArithPath,
    g2IOPath,
    "/shaders/common/g2_ops_main.wgsl",
  ];
}

function g2MSMShaderParts(fpArithShaderPath: string, g2ArithPath: string, g2IOPath: string): readonly string[] {
  return [
    `${fpArithShaderPath}#section=fp-types`,
    `${fpArithShaderPath}#section=fp-consts`,
    `${fpArithShaderPath}#section=fp-core`,
    "/shaders/common/g2_msm_bindings.wgsl",
    g2ArithPath,
    g2IOPath,
    "/shaders/common/g2_msm_jac.wgsl",
  ];
}

const CURVE_DEFINITIONS: Record<SupportedCurveID, CurveDefinition> = {
  bn254: {
    id: "bn254",
    frArithShaderPath: "/shaders/curves/bn254/fr_arith.wgsl",
    frVectorShaderPath: "/shaders/curves/bn254/fr_vector.wgsl",
    frNTTShaderPath: "/shaders/curves/bn254/fr_ntt.wgsl",
    frNTTDomainPath: "/testdata/vectors/fr/bn254_ntt_domains.json",
    frModulusHex: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    fpArithShaderPath: "/shaders/curves/bn254/fp_arith.wgsl",
    g1ArithShaderParts: g1OpsShaderParts("/shaders/curves/bn254/fp_arith.wgsl", "/shaders/curves/bn254/g1_io.wgsl"),
    g1MSMShaderParts: g1MSMShaderParts("/shaders/curves/bn254/fp_arith.wgsl", "/shaders/curves/bn254/g1_io.wgsl"),
    g2ArithShaderParts: g2OpsShaderParts("/shaders/curves/bn254/fp_arith.wgsl", "/shaders/curves/bn254/g2_arith.wgsl", "/shaders/curves/bn254/g2_io.wgsl"),
    g2MSMShaderParts: g2MSMShaderParts("/shaders/curves/bn254/fp_arith.wgsl", "/shaders/curves/bn254/g2_arith.wgsl", "/shaders/curves/bn254/g2_io.wgsl"),
    coordinateBytes: 32,
    pointBytes: 96,
    g2CoordinateBytes: 64,
    g2PointBytes: 192,
    zeroHex: "0000000000000000000000000000000000000000000000000000000000000000",
  },
  bls12_381: {
    id: "bls12_381",
    frArithShaderPath: "/shaders/curves/bls12_381/fr_arith.wgsl",
    frVectorShaderPath: "/shaders/curves/bls12_381/fr_vector.wgsl",
    frNTTShaderPath: "/shaders/curves/bls12_381/fr_ntt.wgsl",
    frNTTDomainPath: "/testdata/vectors/fr/bls12_381_ntt_domains.json",
    frModulusHex: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
    fpArithShaderPath: "/shaders/curves/bls12_381/fp_arith.wgsl",
    g1ArithShaderParts: g1OpsShaderParts("/shaders/curves/bls12_381/fp_arith.wgsl", "/shaders/curves/bls12_381/g1_io.wgsl"),
    g1MSMShaderParts: g1MSMShaderParts("/shaders/curves/bls12_381/fp_arith.wgsl", "/shaders/curves/bls12_381/g1_io.wgsl"),
    g2ArithShaderParts: g2OpsShaderParts("/shaders/curves/bls12_381/fp_arith.wgsl", "/shaders/curves/bls12_381/g2_arith.wgsl", "/shaders/curves/bls12_381/g2_io.wgsl"),
    g2MSMShaderParts: g2MSMShaderParts("/shaders/curves/bls12_381/fp_arith.wgsl", "/shaders/curves/bls12_381/g2_arith.wgsl", "/shaders/curves/bls12_381/g2_io.wgsl"),
    coordinateBytes: 48,
    pointBytes: 144,
    g2CoordinateBytes: 96,
    g2PointBytes: 288,
    zeroHex:
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  },
  bls12_377: {
    id: "bls12_377",
    frArithShaderPath: "/shaders/curves/bls12_377/fr_arith.wgsl",
    frVectorShaderPath: "/shaders/curves/bls12_377/fr_vector.wgsl",
    frNTTShaderPath: "/shaders/curves/bls12_377/fr_ntt.wgsl",
    frNTTDomainPath: "/testdata/vectors/fr/bls12_377_ntt_domains.json",
    frModulusHex: "0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001",
    fpArithShaderPath: "/shaders/curves/bls12_377/fp_arith.wgsl",
    g1ArithShaderParts: g1OpsShaderParts("/shaders/curves/bls12_377/fp_arith.wgsl", "/shaders/curves/bls12_377/g1_io.wgsl"),
    g1MSMShaderParts: g1MSMShaderParts("/shaders/curves/bls12_377/fp_arith.wgsl", "/shaders/curves/bls12_377/g1_io.wgsl"),
    g2ArithShaderParts: g2OpsShaderParts("/shaders/curves/bls12_377/fp_arith.wgsl", "/shaders/curves/bls12_377/g2_arith.wgsl", "/shaders/curves/bls12_377/g2_io.wgsl"),
    g2MSMShaderParts: g2MSMShaderParts("/shaders/curves/bls12_377/fp_arith.wgsl", "/shaders/curves/bls12_377/g2_arith.wgsl", "/shaders/curves/bls12_377/g2_io.wgsl"),
    coordinateBytes: 48,
    pointBytes: 144,
    g2CoordinateBytes: 96,
    g2PointBytes: 288,
    zeroHex:
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  },
};

/**
 * Ordered list of curves currently exposed by the browser library.
 */
export const supportedCurveIds = Object.freeze(Object.keys(CURVE_DEFINITIONS)) as readonly SupportedCurveID[];

/**
 * Return the runtime metadata for a supported curve.
 */
export function curveDefinition(curve: SupportedCurveID): CurveDefinition {
  return CURVE_DEFINITIONS[curve];
}

/**
 * Create the high-level curve module for a supported curve.
 *
 * This establishes the stable public object shape that later steps populate
 * with concrete field, NTT, group, and MSM operations.
 */
export async function createCurveModule(context: CurveGPUContext, curve: SupportedCurveID): Promise<CurveModule> {
  const definition = curveDefinition(curve);
  const frShape = shapeFor(curve, "fr");
  const fpShape = shapeFor(curve, "fp");

  const opsWorkgroupSize = Math.min(context.maxWorkgroupSize, 256);
  const registry = await buildPipelineRegistry({
    device: context.device,
    opsWorkgroupSize,
    opsShaders: [
      { shaderParts: [definition.frArithShaderPath], entryPoint: "fr_ops_main", useWorkgroupOverride: true },
      { shaderParts: [definition.fpArithShaderPath], entryPoint: "fp_ops_main", useWorkgroupOverride: true },
      { shaderParts: definition.g1ArithShaderParts, entryPoint: "g1_ops_main", useWorkgroupOverride: true },
      { shaderParts: definition.g2ArithShaderParts, entryPoint: "g2_ops_main", useWorkgroupOverride: true },
      { shaderParts: [definition.frVectorShaderPath], entryPoint: "fr_vector_main", useWorkgroupOverride: true },
      { shaderParts: [definition.frNTTShaderPath], entryPoint: "fr_ntt_stage_main", useWorkgroupOverride: true },
    ],
    msmShaders: [
      {
        shaderParts: definition.g1MSMShaderParts,
        entryPoints: ["g1_msm_bucket_jac_main", "g1_msm_weight_jac_main", "g1_msm_subsum_jac_main", "g1_msm_combine_jac_main"],
      },
      {
        shaderParts: definition.g2MSMShaderParts,
        entryPoints: ["g2_msm_bucket_jac_main", "g2_msm_weight_jac_main", "g2_msm_subsum_jac_main", "g2_msm_combine_jac_main"],
      },
    ],
    debug: context.debug,
  });

  const g1MsmRuntime = buildJacPippengerRuntime({
    bucket: registry.getMSMKernel("g1_msm_bucket_jac_main"),
    weightJac: registry.getMSMKernel("g1_msm_weight_jac_main"),
    subsumJac: registry.getMSMKernel("g1_msm_subsum_jac_main"),
    combine: registry.getMSMKernel("g1_msm_combine_jac_main"),
  }, 64, context.debug);

  const g2MsmRuntime = buildJacPippengerRuntime({
    bucket: registry.getMSMKernel("g2_msm_bucket_jac_main"),
    weightJac: registry.getMSMKernel("g2_msm_weight_jac_main"),
    subsumJac: registry.getMSMKernel("g2_msm_subsum_jac_main"),
    combine: registry.getMSMKernel("g2_msm_combine_jac_main"),
  }, 32, context.debug);

  const fr = createFieldModule(context, curve, "fr", {
    byteSize: frShape.byteSize,
    entryPoint: "fr_ops_main",
    label: `${curve}-fr`,
    shape: frShape,
    kernel: registry.getOpsKernel("fr_ops_main"),
  });
  const fp = createFieldModule(context, curve, "fp", {
    byteSize: fpShape.byteSize,
    entryPoint: "fp_ops_main",
    label: `${curve}-fp`,
    shape: fpShape,
    kernel: registry.getOpsKernel("fp_ops_main"),
  });
  const g1 = createG1Module(
    context,
    {
      curve: definition.id,
      coordinateBytes: definition.coordinateBytes,
      pointBytes: definition.pointBytes,
      zeroHex: definition.zeroHex,
      kernel: registry.getOpsKernel("g1_ops_main"),
    },
    fp,
  );
  const g2 = createG2Module(
    context,
    {
      curve: definition.id,
      componentBytes: fpShape.byteSize,
      coordinateBytes: definition.g2CoordinateBytes,
      pointBytes: definition.g2PointBytes,
      kernel: registry.getOpsKernel("g2_ops_main"),
    },
    fp,
  );
  const ntt = createNTTModule(
    context,
    {
      curve: definition.id,
      domainPath: definition.frNTTDomainPath ?? "",
      modulusHex: definition.frModulusHex ?? "",
      vectorKernel: registry.getOpsKernel("fr_vector_main"),
      fieldKernel: registry.getOpsKernel("fr_ops_main"),
      nttKernel: registry.getOpsKernel("fr_ntt_stage_main"),
    },
    fr,
  );
  const g1msm = createG1MSMModule(
    context,
    {
      curve: definition.id,
      coordinateBytes: definition.coordinateBytes,
      pointBytes: definition.pointBytes,
      runtime: g1MsmRuntime,
    },
    fp,
    g1,
  );
  const g2msm = createG2MSMModule(
    context,
    {
      curve: definition.id,
      componentBytes: fpShape.byteSize,
      pointBytes: definition.g2PointBytes,
      runtime: g2MsmRuntime,
    },
    g2,
    fp,
  );
  const groth16 = createGroth16Module({
    context,
    curve: definition.id,
    modulusHex: definition.frModulusHex ?? "",
    frBytes: frShape.byteSize,
    quotient: ntt,
    g1,
    g2,
    g1msm,
    g2msm,
  });
  const plonkQuotient = createPlonkQuotientModule({
    context,
    curve: definition.id,
    fr,
    ntt,
  });
  const plonk = createPlonkModule({
    context,
    curve: definition.id,
    modulusHex: definition.frModulusHex ?? "",
    frBytes: frShape.byteSize,
    fr,
    ntt,
    quotient: plonkQuotient,
    g1,
    g1msm,
  });
  return {
    id: curve,
    context,
    fr,
    fp,
    g1,
    g2,
    ntt,
    groth16,
    plonk,
    g1msm,
    g2msm,
  };
}

/**
 * Create the BN254 module bound to an existing context.
 */
export function createBN254(context: CurveGPUContext): Promise<CurveModule> {
  return createCurveModule(context, "bn254");
}

/**
 * Create the BLS12-381 module bound to an existing context.
 */
export function createBLS12381(context: CurveGPUContext): Promise<CurveModule> {
  return createCurveModule(context, "bls12_381");
}

/**
 * Create the BLS12-377 module bound to an existing context.
 */
export function createBLS12377(context: CurveGPUContext): Promise<CurveModule> {
  return createCurveModule(context, "bls12_377");
}
