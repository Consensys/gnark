import type { FieldShape } from "./types.js";
import type { BufferPool } from "./buffer_pool.js";

export type { CurveGPUError, CurveGPUNotSupportedError, CurveGPUDeviceLostError, CurveGPUShaderError } from "./errors.js";

/**
 * Curves currently exposed by the browser library surface.
 */
export type SupportedCurveID = "bn254" | "bls12_381" | "bls12_377";

/**
 * Canonical byte representation for field and scalar values.
 *
 * For `fr` and `fp` module operations, values are little-endian byte strings
 * in Montgomery form unless explicitly converted with
 * `toMontgomery` / `fromMontgomery`.
 *
 * For G1 scalar multiplication and MSM, scalars are little-endian 32-byte
 * scalar-field elements in regular form.
 */
export type CurveGPUElementBytes = Uint8Array;

/**
 * Affine G1 point represented as little-endian field-element byte strings.
 *
 * Coordinates use the same field representation as the curve fixtures and
 * shader interfaces for the selected curve.
 */
export interface CurveGPUAffinePoint {
  x: Uint8Array;
  y: Uint8Array;
}

/**
 * Jacobian G1 point represented as little-endian field-element byte strings.
 */
export interface CurveGPUJacobianPoint {
  x: Uint8Array;
  y: Uint8Array;
  z: Uint8Array;
}

/**
 * Quadratic-extension field element represented as two base-field coordinates.
 *
 * Values are little-endian byte strings in the same base-field representation
 * used by the selected curve's `fp` module.
 */
export interface CurveGPUFp2Element {
  c0: Uint8Array;
  c1: Uint8Array;
}

/**
 * Affine G2 point represented over the quadratic extension field.
 */
export interface CurveGPUG2AffinePoint {
  x: CurveGPUFp2Element;
  y: CurveGPUFp2Element;
}

/**
 * Jacobian G2 point represented over the quadratic extension field.
 */
export interface CurveGPUG2JacobianPoint {
  x: CurveGPUFp2Element;
  y: CurveGPUFp2Element;
  z: CurveGPUFp2Element;
}

/**
 * Options for affine MSM execution.
 *
 * All fields are optional; sensible defaults are chosen automatically.
 */
export type CurveGPUMSMOptions = {
  /**
   * Number of independent MSM instances to compute in a single call.
   * Each instance uses `termsPerInstance` consecutive base/scalar pairs
   * from the input arrays. Defaults to `1`.
   */
  count?: number;
  /**
   * Number of (base, scalar) pairs per MSM instance. When `count` is 1 and
   * this field is omitted, the full length of the input arrays is used.
   */
  termsPerInstance?: number;
  /**
   * Pippenger window size in bits. If omitted, the library selects a window
   * size based on `termsPerInstance` via `bestWindow()`.
   */
  window?: number;
  /**
   * Maximum number of terms processed per GPU dispatch chunk. Smaller values
   * reduce peak GPU memory usage at the cost of more dispatches. Defaults to
   * `256`.
   */
  maxChunkSize?: number;
};

/**
 * Supported packed point encodings for bulk APIs.
 *
 * `"jacobian_x_y_z_le"` — Six consecutive little-endian field-element byte
 * strings in the order `x, y, z`. For affine points represented in Jacobian
 * form set `z` to the Montgomery-form one element; for the point at infinity
 * leave all six components zero-filled.
 */
export type CurveGPUPackedPointLayout = "jacobian_x_y_z_le";

/**
 * Subset of device limits that matter for the current curve workloads.
 */
export type CurveGPURequestedLimits = {
  /** Maximum byte size of a single storage buffer binding. */
  maxStorageBufferBindingSize?: number;
  /** Maximum byte size of a GPU buffer. */
  maxBufferSize?: number;
};

/**
 * Human-readable adapter details useful for logging, debugging, and telemetry.
 */
export type CurveGPUAdapterDiagnostics = {
  /** GPU vendor string, e.g. `"apple"`, `"nvidia"`, `"intel"`. */
  vendor?: string;
  /** GPU architecture string, e.g. `"common-3"`. */
  architecture?: string;
  /** Free-form GPU description provided by the driver. */
  description?: string;
  /** Whether the browser selected a software (fallback) adapter. */
  isFallbackAdapter?: boolean;
};

/**
 * Options for acquiring a browser WebGPU context.
 */
export type CurveGPUContextOptions = {
  /**
   * Hint to the browser about which GPU to prefer on multi-GPU systems.
   * `"high-performance"` requests a discrete GPU; `"low-power"` requests an
   * integrated GPU. Defaults to the browser's own selection.
   */
  powerPreference?: GPUPowerPreference;
  /**
   * When `true` (the default), the adapter's reported limits for
   * `maxStorageBufferBindingSize` and `maxBufferSize` are propagated to
   * `requestDevice`. Set to `false` to request a device with default limits,
   * which may restrict the maximum MSM size.
   */
  requireAdapterLimits?: boolean;
  /**
   * Explicit device limits to request, overriding the adapter-derived values.
   * Useful when you know the exact buffer sizes your workload needs.
   */
  requiredLimits?: CurveGPURequestedLimits;
  /** Enable verbose debug logging from GPU operations. Defaults to `false`. */
  debug?: boolean;
};

/**
 * Shared browser WebGPU context for all curve operations.
 *
 * This is the top-level object a consumer creates once, then reuses for
 * field, group, NTT, and MSM work.
 */
export interface CurveGPUContext {
  /** The underlying WebGPU adapter selected by the browser. */
  readonly adapter: GPUAdapter;
  /** The WebGPU logical device used for all GPU operations. */
  readonly device: GPUDevice;
  /** Adapter metadata, or `null` if `requestAdapterInfo()` is unavailable. */
  readonly adapterInfo: GPUAdapterInfo | null;
  /** Human-readable diagnostics derived from the adapter. */
  readonly diagnostics: CurveGPUAdapterDiagnostics;
  /** Limits that were requested when the device was created. */
  readonly requestedLimits: CurveGPURequestedLimits;
  /** Whether verbose debug logging is enabled for GPU operations. */
  readonly debug: boolean;
  /** Maximum compute workgroup size supported by the device. */
  readonly maxWorkgroupSize: number;
  /** GPU buffer pool shared across all operations on this context. */
  readonly bufferPool: BufferPool;
  /**
   * Resolves when the GPU device is lost.
   *
   * Consumers can attach a handler to this promise to react to unexpected
   * device loss (driver crash, GPU reset, tab backgrounded on mobile, etc.).
   * The resolved value is the browser's `GPUDeviceLostInfo` object.
   */
  readonly deviceLost: Promise<GPUDeviceLostInfo>;
  /**
   * Release any library-owned resources associated with the context.
   *
   * Drains the buffer pool and performs any other cleanup. Browser WebGPU
   * device lifetime is still managed by the browser, so this is a logical
   * shutdown hook rather than a hard device destroy.
   */
  close(): void;
}

/**
 * Field arithmetic bound to a specific curve field.
 *
 * All methods except `toMontgomery` and `fromMontgomery` operate on
 * Montgomery-form little-endian byte strings.
 *
 * Batch variants execute the same operation element-wise over equal-length
 * slices.
 */
export interface FieldModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly field: "fr" | "fp";
  readonly shape: FieldShape;
  readonly byteSize: number;
  /** Return the additive identity as a zero-filled byte string. */
  zero(): CurveGPUElementBytes;
  /** Copy one element through the GPU implementation. */
  copy(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  copyBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Return the multiplicative identity in Montgomery form. */
  montOne(): Promise<CurveGPUElementBytes>;
  /** Check modular equality. */
  equal(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<boolean>;
  equalBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<boolean[]>;
  /** Modular addition. */
  add(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  addBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular subtraction. */
  sub(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  subBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular negation. */
  neg(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  negBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular doubling. */
  double(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  doubleBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular multiplication. */
  mul(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  mulBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Element-wise multiplication over packed Montgomery-form field elements. */
  mulPackedMont(a: Uint8Array, b: Uint8Array): Promise<Uint8Array>;
  /** Modular squaring. */
  square(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  squareBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Reduce a value into canonical Montgomery form. */
  normalizeMont(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  normalizeMontBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Convert a regular little-endian field element into Montgomery form. */
  toMontgomery(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  toMontgomeryBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /**
   * Convert a packed sequence of regular little-endian field elements into
   * Montgomery form.
   */
  toMontgomeryPacked(values: Uint8Array): Promise<Uint8Array>;
  /** Convert a Montgomery-form element back into regular little-endian bytes. */
  fromMontgomery(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  fromMontgomeryBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /**
   * Convert a packed sequence of Montgomery-form field elements back into
   * regular little-endian bytes.
   */
  fromMontgomeryPacked(values: Uint8Array): Promise<Uint8Array>;
}

/**
 * G1 point operations for a specific curve.
 *
 * Affine inputs are passed as `x` and `y` byte strings. Jacobian outputs use
 * three coordinates in the same field representation as the selected curve.
 */
export interface G1Module {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly coordinateBytes: number;
  readonly pointBytes: number;
  readonly zeroHex: string;
  /** Return the affine point at infinity (all-zero coordinates). */
  affineInfinity(): CurveGPUAffinePoint;
  /** Return the zero Jacobian point (all-zero coordinates) synchronously. */
  jacobianZero(): CurveGPUJacobianPoint;
  /** Copy a Jacobian point through the GPU implementation. */
  copy(point: CurveGPUJacobianPoint): Promise<CurveGPUJacobianPoint>;
  copyBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUJacobianPoint[]>;
  /** Construct the Jacobian point at infinity via the GPU. */
  jacobianInfinity(): Promise<CurveGPUJacobianPoint>;
  jacobianInfinityBatch(count: number): Promise<CurveGPUJacobianPoint[]>;
  /** Lift affine points into Jacobian coordinates. */
  affineToJacobian(point: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint>;
  affineToJacobianBatch(points: readonly CurveGPUAffinePoint[]): Promise<CurveGPUJacobianPoint[]>;
  /** Negate Jacobian points. */
  negJacobian(point: CurveGPUJacobianPoint): Promise<CurveGPUJacobianPoint>;
  negJacobianBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUJacobianPoint[]>;
  /** Double Jacobian points. */
  doubleJacobian(point: CurveGPUJacobianPoint): Promise<CurveGPUJacobianPoint>;
  doubleJacobianBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUJacobianPoint[]>;
  /** Add an affine point into a Jacobian accumulator (mixed addition). */
  addMixed(point: CurveGPUJacobianPoint, affine: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint>;
  addMixedBatch(points: readonly CurveGPUJacobianPoint[], affine: readonly CurveGPUAffinePoint[]): Promise<CurveGPUJacobianPoint[]>;
  /**
   * Convert Jacobian points to affine coordinates.
   *
   * The returned object keeps the `z` field for compatibility with existing
   * fixtures; consumers that need a strict affine point should use `x` and `y`.
   */
  jacobianToAffine(point: CurveGPUJacobianPoint): Promise<CurveGPUAffinePoint>;
  jacobianToAffineBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUAffinePoint[]>;
  /** Add two affine points and return the result in Jacobian form. */
  affineAdd(a: CurveGPUAffinePoint, b: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint>;
  affineAddBatch(a: readonly CurveGPUAffinePoint[], b: readonly CurveGPUAffinePoint[]): Promise<CurveGPUJacobianPoint[]>;
  /** Multiply an affine base by a scalar and return the result in Jacobian form. */
  scalarMulAffine(base: CurveGPUAffinePoint, scalar: CurveGPUElementBytes): Promise<CurveGPUJacobianPoint>;
  scalarMulAffineBatch(bases: readonly CurveGPUAffinePoint[], scalars: readonly CurveGPUElementBytes[]): Promise<CurveGPUJacobianPoint[]>;
  /** Add two affine points and return the result in affine form. */
  addAffine(a: CurveGPUAffinePoint, b: CurveGPUAffinePoint): Promise<CurveGPUAffinePoint>;
  addAffineBatch(a: readonly CurveGPUAffinePoint[], b: readonly CurveGPUAffinePoint[]): Promise<CurveGPUAffinePoint[]>;
  /** Negate an affine point and return the result in affine form. */
  negAffine(point: CurveGPUAffinePoint): Promise<CurveGPUAffinePoint>;
  negAffineBatch(points: readonly CurveGPUAffinePoint[]): Promise<CurveGPUAffinePoint[]>;
  /** Double an affine point and return the result in affine form. */
  doubleAffine(point: CurveGPUAffinePoint): Promise<CurveGPUAffinePoint>;
  doubleAffineBatch(points: readonly CurveGPUAffinePoint[]): Promise<CurveGPUAffinePoint[]>;
  /** Multiply an affine base by a scalar and return the result in affine form. */
  scalarMulAffineResult(base: CurveGPUAffinePoint, scalar: CurveGPUElementBytes): Promise<CurveGPUAffinePoint>;
  scalarMulAffineResultBatch(bases: readonly CurveGPUAffinePoint[], scalars: readonly CurveGPUElementBytes[]): Promise<CurveGPUAffinePoint[]>;
}

/**
 * G2 point operations for a specific curve.
 *
 * Coordinates are represented over the quadratic extension field as `{c0, c1}`
 * byte-string pairs. The arithmetic rules mirror `G1Module` but operate on
 * `CurveGPUG2AffinePoint` and `CurveGPUG2JacobianPoint` types.
 */
export interface G2Module {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  /** Byte size of one base-field component (`c0` or `c1`). */
  readonly componentBytes: number;
  /** Byte size of one G2 coordinate (two components: `2 * componentBytes`). */
  readonly coordinateBytes: number;
  /** Byte size of one G2 Jacobian point (six components: `6 * componentBytes`). */
  readonly pointBytes: number;
  /** Return the affine G2 point at infinity (all-zero components). */
  affineInfinity(): CurveGPUG2AffinePoint;
  /** Return the zero G2 Jacobian point (all-zero components) synchronously. */
  jacobianZero(): CurveGPUG2JacobianPoint;
  /** Copy a G2 Jacobian point through the GPU implementation. */
  copy(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2JacobianPoint>;
  copyBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2JacobianPoint[]>;
  /** Construct the G2 Jacobian point at infinity via the GPU. */
  jacobianInfinity(): Promise<CurveGPUG2JacobianPoint>;
  jacobianInfinityBatch(count: number): Promise<CurveGPUG2JacobianPoint[]>;
  /** Lift affine G2 points into Jacobian coordinates. */
  affineToJacobian(point: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint>;
  affineToJacobianBatch(points: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2JacobianPoint[]>;
  /** Negate G2 Jacobian points. */
  negJacobian(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2JacobianPoint>;
  negJacobianBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2JacobianPoint[]>;
  /** Double G2 Jacobian points. */
  doubleJacobian(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2JacobianPoint>;
  doubleJacobianBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2JacobianPoint[]>;
  /** Add an affine G2 point into a Jacobian accumulator (mixed addition). */
  addMixed(point: CurveGPUG2JacobianPoint, affine: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint>;
  addMixedBatch(points: readonly CurveGPUG2JacobianPoint[], affine: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2JacobianPoint[]>;
  /**
   * Convert G2 Jacobian points to affine coordinates.
   *
   * Returns affine points; the `z` component is not present in the result type.
   */
  jacobianToAffine(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2AffinePoint>;
  jacobianToAffineBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2AffinePoint[]>;
  /** Add two affine G2 points and return the result in Jacobian form. */
  affineAdd(a: CurveGPUG2AffinePoint, b: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint>;
  affineAddBatch(a: readonly CurveGPUG2AffinePoint[], b: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2JacobianPoint[]>;
  /** Multiply an affine G2 base by a scalar and return the result in Jacobian form. */
  scalarMulAffine(base: CurveGPUG2AffinePoint, scalar: CurveGPUElementBytes): Promise<CurveGPUG2JacobianPoint>;
  scalarMulAffineBatch(bases: readonly CurveGPUG2AffinePoint[], scalars: readonly CurveGPUElementBytes[]): Promise<CurveGPUG2JacobianPoint[]>;
  /** Add two affine G2 points and return the result in affine form. */
  addAffine(a: CurveGPUG2AffinePoint, b: CurveGPUG2AffinePoint): Promise<CurveGPUG2AffinePoint>;
  addAffineBatch(a: readonly CurveGPUG2AffinePoint[], b: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2AffinePoint[]>;
  /** Negate an affine G2 point and return the result in affine form. */
  negAffine(point: CurveGPUG2AffinePoint): Promise<CurveGPUG2AffinePoint>;
  negAffineBatch(points: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2AffinePoint[]>;
  /** Double an affine G2 point and return the result in affine form. */
  doubleAffine(point: CurveGPUG2AffinePoint): Promise<CurveGPUG2AffinePoint>;
  doubleAffineBatch(points: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2AffinePoint[]>;
  /** Multiply an affine G2 base by a scalar and return the result in affine form. */
  scalarMulAffineResult(base: CurveGPUG2AffinePoint, scalar: CurveGPUElementBytes): Promise<CurveGPUG2AffinePoint>;
  scalarMulAffineResultBatch(bases: readonly CurveGPUG2AffinePoint[], scalars: readonly CurveGPUElementBytes[]): Promise<CurveGPUG2AffinePoint[]>;
}

/**
 * Scalar-field NTT module for a specific curve.
 */
export interface NTTModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly field: "fr";
  /** Report the power-of-two domain sizes available from loaded metadata. */
  supportedSizes(): Promise<number[]>;
  /** Run the forward NTT over a power-of-two batch of Montgomery-form values. */
  forward(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Run the inverse NTT over a power-of-two batch of Montgomery-form values. */
  inverse(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Run the forward NTT over packed regular little-endian field elements. */
  forwardPackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Run the inverse NTT over packed regular little-endian field elements. */
  inversePackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Run the inverse NTT over bit-reversed packed regular little-endian field elements. */
  inverseBitReversePackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Convert packed regular little-endian values from Lagrange coset form to canonical regular form. */
  inverseCosetPackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Run the forward NTT over packed Montgomery-form field elements. */
  forwardPackedMont(values: Uint8Array): Promise<Uint8Array>;
  /** Run the inverse NTT over packed Montgomery-form field elements. */
  inversePackedMont(values: Uint8Array): Promise<Uint8Array>;
  /** Run forward NTTs over packed Montgomery-form vectors of equal size. */
  forwardPackedMontBatch(values: Uint8Array, vectorSize: number, vectorCount: number): Promise<Uint8Array>;
  /** Run inverse NTTs over packed Montgomery-form vectors of equal size. */
  inversePackedMontBatch(values: Uint8Array, vectorSize: number, vectorCount: number): Promise<Uint8Array>;
  /**
   * Convert packed regular little-endian values from bit-reversed Lagrange
   * coset form to canonical regular form.
   */
  inverseCosetBitReversePackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Precompute and cache domain metadata for a power-of-two domain size. */
  prewarmDomain(size: number): Promise<void>;
}

/**
 * Groth16 quotient helpers.
 *
 * These methods are separated from the generic NTT module even though they reuse
 * the same NTT/vector kernels internally.
 */
export interface Groth16QuotientModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  /**
   * Compute the Groth16 quotient vector H from packed regular little-endian
   * A, B, and C witness polynomials already padded to the FFT domain size.
   *
   * The returned packed vector is in regular little-endian coefficient form
   * and has the same element count as the padded inputs.
  */
  computeGroth16QuotientPackedRegular(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array>;
  /**
   * Compute the Groth16 quotient vector H from packed Montgomery little-endian
   * A, B, and C witness polynomials already padded to the FFT domain size.
   *
   * The returned packed vector is in regular little-endian coefficient form
   * and has the same element count as the padded inputs.
   */
  computeGroth16QuotientPackedMont(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array>;
  /** Precompute and cache Groth16 quotient-domain data for a power-of-two domain size. */
  prewarmGroth16QuotientDomain(size: number): Promise<void>;
}

export type Groth16ProvingKeyFormat = "serialized" | "dump";
export type Groth16RuntimeKind = "webgpu" | "native";

export type Groth16RuntimeOptions = {
  /** Optional URL for Go's wasm_exec.js runtime shim. Defaults to the package asset. */
  wasmExecURL?: string;
  /** Optional URL for the WebGPU-accelerated Groth16 Go WASM runtime. Defaults to the package asset. */
  webgpuWasmURL?: string;
  /** Optional URL for the native gnark Groth16 Go WASM runtime. Defaults to the package asset. */
  nativeWasmURL?: string;
};

export interface Groth16Handle {
  /** Release the corresponding Go WASM runtime handle. */
  dispose(): Promise<void>;
}

export interface Groth16ConstraintSystem extends Groth16Handle {
  /** Number of constraints reported by the deserialized constraint system. */
  readonly constraints: number;
}

export type Groth16ProvingKey = Groth16Handle;
export type Groth16VerificationKey = Groth16Handle;

/**
 * Browser Groth16 proof helpers backed by a long-lived Go WASM runtime.
 */
export interface Groth16Module extends Groth16QuotientModule {
  /**
   * Load the Go WASM Groth16 runtime.
   *
   * Defaults to the WebGPU runtime and package-shipped assets. Override URLs
   * when serving the runtime from an application asset path or CDN.
   */
  loadRuntime(options?: Groth16RuntimeOptions & { kind?: Groth16RuntimeKind }): Promise<void>;
  /** Deserialize a gnark Groth16 constraint system. */
  readConstraintSystem(bytes: Uint8Array): Promise<Groth16ConstraintSystem>;
  /** Deserialize a gnark Groth16 proving key. */
  readProvingKey(bytes: Uint8Array, options?: { format?: Groth16ProvingKeyFormat }): Promise<Groth16ProvingKey>;
  /** Deserialize a gnark Groth16 verification key. */
  readVerificationKey(bytes: Uint8Array): Promise<Groth16VerificationKey>;
  /** Precompute browser-side proving key caches. */
  prepareProvingKey(pk: Groth16ProvingKey): Promise<void>;
  /** Prove with a gnark binary witness and return gnark-serialized proof bytes. */
  prove(ccs: Groth16ConstraintSystem, pk: Groth16ProvingKey, witness: Uint8Array): Promise<Uint8Array>;
  /** Verify gnark-serialized proof bytes against a gnark binary public witness. */
  verify(proof: Uint8Array, vk: Groth16VerificationKey, publicWitness: Uint8Array): Promise<boolean>;
  /**
   * Encode flat regular field values as a gnark binary witness.
   *
   * Values must be ordered `[public | private]`. The binary witness protocol
   * stores field elements as fixed-width big-endian bytes.
   */
  encodeWitness(values: readonly bigint[], options: { publicCount: number }): Uint8Array;
}

export type PlonkProvingKeyFormat = "serialized" | "unsafe";
export type PlonkRuntimeKind = "webgpu" | "native";

export type PlonkRuntimeOptions = {
  /** Optional URL for Go's wasm_exec.js runtime shim. Defaults to the package asset. */
  wasmExecURL?: string;
  /** Optional URL for the WebGPU-accelerated PLONK Go WASM runtime. Defaults to the package asset. */
  webgpuWasmURL?: string;
  /** Optional URL for the native gnark PLONK Go WASM runtime. Defaults to the package asset. */
  nativeWasmURL?: string;
};

export interface PlonkHandle {
  /** Release the corresponding Go WASM runtime handle. */
  dispose(): Promise<void>;
}

export interface PlonkConstraintSystem extends PlonkHandle {
  /** Number of constraints reported by the deserialized constraint system. */
  readonly constraints: number;
}

export type PlonkProvingKey = PlonkHandle;
export type PlonkVerificationKey = PlonkHandle;

/**
 * Browser PLONK proof helpers backed by a long-lived Go WASM runtime.
 */
export interface PlonkModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  /**
   * Load the Go WASM PLONK runtime.
   *
   * Defaults to the WebGPU runtime and package-shipped assets. Override URLs
   * when serving the runtime from an application asset path or CDN.
   */
  loadRuntime(options?: PlonkRuntimeOptions & { kind?: PlonkRuntimeKind }): Promise<void>;
  /** Deserialize a gnark PLONK constraint system. */
  readConstraintSystem(bytes: Uint8Array): Promise<PlonkConstraintSystem>;
  /** Deserialize a gnark PLONK proving key. */
  readProvingKey(bytes: Uint8Array, options?: { format?: PlonkProvingKeyFormat }): Promise<PlonkProvingKey>;
  /** Deserialize a gnark PLONK verification key. */
  readVerificationKey(bytes: Uint8Array): Promise<PlonkVerificationKey>;
  /**
   * Precompute browser-side proving key caches.
   *
   * Passing the constraint system lets the WebGPU runtime prepare PLONK
   * trace-derived caches outside the timed prove path.
   */
  prepareProvingKey(pk: PlonkProvingKey, ccs?: PlonkConstraintSystem): Promise<void>;
  /** Prove with a gnark binary witness and return gnark-serialized proof bytes. */
  prove(ccs: PlonkConstraintSystem, pk: PlonkProvingKey, witness: Uint8Array): Promise<Uint8Array>;
  /** Verify gnark-serialized proof bytes against a gnark binary public witness. */
  verify(proof: Uint8Array, vk: PlonkVerificationKey, publicWitness: Uint8Array): Promise<boolean>;
  /**
   * Encode flat regular field values as a gnark binary witness.
   *
   * Values must be ordered `[public | private]`. The binary witness protocol
   * stores field elements as fixed-width big-endian bytes.
   */
  encodeWitness(values: readonly bigint[], options: { publicCount: number }): Uint8Array;
}

/**
 * Multi-scalar multiplication module over G1 affine bases.
 */
export interface G1MSMModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly group: "g1";
  /** Choose the default Pippenger window size for a given term count. */
  bestWindow(termCount: number): number;
  /** Run a single affine-base Pippenger MSM and return the result in Jacobian form. */
  pippengerAffine(
    bases: readonly CurveGPUAffinePoint[],
    scalars: readonly CurveGPUElementBytes[],
    options?: CurveGPUMSMOptions,
  ): Promise<CurveGPUJacobianPoint>;
  /** Run a single affine-base Pippenger MSM and return the result in affine form. */
  pippengerAffineResult(
    bases: readonly CurveGPUAffinePoint[],
    scalars: readonly CurveGPUElementBytes[],
    options?: CurveGPUMSMOptions,
  ): Promise<CurveGPUAffinePoint>;
  /**
   * Run a batched affine-base Pippenger MSM.
   *
   * `bases` and `scalars` are interleaved: the first `termsPerInstance` pairs
   * belong to instance 0, the next `termsPerInstance` pairs to instance 1, etc.
   * `options.count` and `options.termsPerInstance` must both be provided.
   */
  pippengerAffineBatch(
    bases: readonly CurveGPUAffinePoint[],
    scalars: readonly CurveGPUElementBytes[],
    options: CurveGPUMSMOptions,
  ): Promise<CurveGPUJacobianPoint[]>;
  /**
   * Run affine-base Pippenger MSM from packed bytes.
   *
   * `basesPacked` is currently expected in `jacobian_x_y_z_le` layout with one
   * packed point per term. For ordinary affine points, `z` should be the
   * Montgomery-form one element and infinity points should remain zero-filled.
   *
   * `scalarsPacked` is a packed sequence of regular-form 32-byte scalars.
   *
   * The result is returned in the same packed `jacobian_x_y_z_le` layout.
   */
  pippengerPackedJacobianBases(
    basesPacked: Uint8Array,
    scalarsPacked: Uint8Array,
    options: CurveGPUMSMOptions & { layout?: CurveGPUPackedPointLayout },
  ): Promise<Uint8Array>;
}

/**
 * Multi-scalar multiplication module over G2 affine bases.
 *
 * The API mirrors `G1MSMModule` but operates on G2 points over the quadratic
 * extension field. Bases are supplied in affine form; results are returned in
 * Jacobian form unless an `AffineResult` variant is used.
 */
export interface G2MSMModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly group: "g2";
  /** Choose the default Pippenger window size for a given term count. */
  bestWindow(termCount: number): number;
  /** Run a single affine-base G2 Pippenger MSM and return the result in Jacobian form. */
  pippengerAffine(
    bases: readonly CurveGPUG2AffinePoint[],
    scalars: readonly CurveGPUElementBytes[],
    options?: CurveGPUMSMOptions,
  ): Promise<CurveGPUG2JacobianPoint>;
  /** Run a single affine-base G2 Pippenger MSM and return the result in affine form. */
  pippengerAffineResult(
    bases: readonly CurveGPUG2AffinePoint[],
    scalars: readonly CurveGPUElementBytes[],
    options?: CurveGPUMSMOptions,
  ): Promise<CurveGPUG2AffinePoint>;
  /**
   * Run a batched affine-base G2 Pippenger MSM.
   *
   * `bases` and `scalars` are interleaved: the first `termsPerInstance` pairs
   * belong to instance 0, the next `termsPerInstance` pairs to instance 1, etc.
   * `options.count` and `options.termsPerInstance` must both be provided.
   */
  pippengerAffineBatch(
    bases: readonly CurveGPUG2AffinePoint[],
    scalars: readonly CurveGPUElementBytes[],
    options: CurveGPUMSMOptions,
  ): Promise<CurveGPUG2JacobianPoint[]>;
  /**
   * Run G2 Pippenger MSM from packed bytes.
   *
   * `basesPacked` must be in `jacobian_x_y_z_le` layout: six consecutive
   * base-field components per point (`x.c0, x.c1, y.c0, y.c1, z.c0, z.c1`).
   * Set `z.c0` to the Montgomery-form one element for affine inputs; leave all
   * components zero for the point at infinity.
   *
   * `scalarsPacked` is a packed sequence of regular-form 32-byte scalars.
   *
   * The result is returned in the same packed `jacobian_x_y_z_le` layout,
   * one Jacobian point per MSM instance.
   */
  pippengerPackedJacobianBases(
    basesPacked: Uint8Array,
    scalarsPacked: Uint8Array,
    options: CurveGPUMSMOptions & { layout?: CurveGPUPackedPointLayout },
  ): Promise<Uint8Array>;
}

/**
 * High-level curve module returned by the library.
 *
 * This groups the curve-specific submodules behind one stable object per
 * supported curve. Obtain an instance via `createCurveModule` (or the
 * curve-specific helpers `createBN254` / `createBLS12381`).
 */
export interface CurveModule {
  /** The curve this module was created for. */
  readonly id: SupportedCurveID;
  /** The WebGPU context shared across all submodules. */
  readonly context: CurveGPUContext;
  /** Scalar-field (`Fr`) arithmetic. */
  readonly fr: FieldModule;
  /** Base-field (`Fp`) arithmetic. */
  readonly fp: FieldModule;
  /** G1 point operations. */
  readonly g1: G1Module;
  /** G2 point operations over the quadratic extension field. */
  readonly g2: G2Module;
  /** Scalar-field NTT. */
  readonly ntt: NTTModule;
  /** Groth16-specific scalar-field helpers. */
  readonly groth16: Groth16Module;
  /** PLONK proof helpers. */
  readonly plonk: PlonkModule;
  /** Multi-scalar multiplication over G1. */
  readonly g1msm: G1MSMModule;
  /** Multi-scalar multiplication over G2. */
  readonly g2msm: G2MSMModule;
}
