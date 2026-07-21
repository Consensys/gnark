export type CurveID = "bn254" | "bls12_381" | "bls12_377";
export type FieldID = "fr" | "fp";

export interface FieldShape {
  curve: CurveID;
  field: FieldID;
  hostWords: 4 | 6;
  gpuLimbs: 8 | 12;
  byteSize: 32 | 48;
}

export type U32x8 = Uint32Array & { length: 8 };
export type U32x12 = Uint32Array & { length: 12 };

const GENERATED_SHAPES = {
  bn254: {
    fr: {
      curve: "bn254",
      field: "fr",
      hostWords: 4,
      gpuLimbs: 8,
      byteSize: 32,
    },
    fp: {
      curve: "bn254",
      field: "fp",
      hostWords: 4,
      gpuLimbs: 8,
      byteSize: 32,
    },
  },
  bls12_381: {
    fr: {
      curve: "bls12_381",
      field: "fr",
      hostWords: 4,
      gpuLimbs: 8,
      byteSize: 32,
    },
    fp: {
      curve: "bls12_381",
      field: "fp",
      hostWords: 6,
      gpuLimbs: 12,
      byteSize: 48,
    },
  },
  bls12_377: {
    fr: {
      curve: "bls12_377",
      field: "fr",
      hostWords: 4,
      gpuLimbs: 8,
      byteSize: 32,
    },
    fp: {
      curve: "bls12_377",
      field: "fp",
      hostWords: 6,
      gpuLimbs: 12,
      byteSize: 48,
    },
  },
} as const;

export function shapeFor(curve: CurveID, field: FieldID): FieldShape {
  const fields = GENERATED_SHAPES[curve];
  if (!fields) {
    throw new Error(`unsupported curve ${curve}`);
  }
  const shape = fields[field];
  if (!shape) {
    throw new Error(`unsupported field ${field} for curve ${curve}`);
  }
  return shape;
}
