import type { CurveGPUContext, CurveGPUElementBytes, FieldModule, SupportedCurveID } from "./api.js";
import type { SimpleKernel } from "./runtime_common.js";
import {
  cloneBytes,
  ensureByteLength,
  lazyAsync,
  packElementBatch,
  runSimpleKernel,
  unpackElementBatch,
} from "./runtime_common.js";

const OP_COPY = 0;
const OP_ONE = 2;
const OP_ADD = 3;
const OP_SUB = 4;
const OP_NEG = 5;
const OP_DOUBLE = 6;
const OP_NORMALIZE = 7;
const OP_EQUAL = 8;
const OP_MUL = 9;
const OP_SQUARE = 10;
const OP_TO_MONT = 11;
const OP_FROM_MONT = 12;

type FieldOpCode =
  | typeof OP_COPY
  | typeof OP_ONE
  | typeof OP_ADD
  | typeof OP_SUB
  | typeof OP_NEG
  | typeof OP_DOUBLE
  | typeof OP_NORMALIZE
  | typeof OP_EQUAL
  | typeof OP_MUL
  | typeof OP_SQUARE
  | typeof OP_TO_MONT
  | typeof OP_FROM_MONT;

function zeros(count: number, byteSize: number): Uint8Array[] {
  return Array.from({ length: count }, () => new Uint8Array(byteSize));
}

function isNonZero(bytes: Uint8Array): boolean {
  return bytes.some((byte) => byte !== 0);
}

function ensurePackedElements(bytes: Uint8Array, byteSize: number, label: string): number {
  if (bytes.byteLength % byteSize !== 0) {
    throw new Error(`${label}: expected a multiple of ${byteSize} bytes, got ${bytes.byteLength}`);
  }
  return bytes.byteLength / byteSize;
}

export function createFieldModule(
  context: CurveGPUContext,
  curve: SupportedCurveID,
  field: "fr" | "fp",
  options: {
    byteSize: number;
    kernel: SimpleKernel;
    entryPoint: "fr_ops_main" | "fp_ops_main";
    label: string;
    shape: FieldModule["shape"];
  },
): FieldModule {
  const { byteSize, kernel, entryPoint: _entryPoint, label, shape } = options;
  const zeroValue = new Uint8Array(byteSize);

  async function runPacked(opcode: FieldOpCode, inputA: Uint8Array, inputB?: Uint8Array): Promise<Uint8Array> {
    const count = ensurePackedElements(inputA, byteSize, `${label}.packedA`);
    const b = inputB ?? new Uint8Array(inputA.byteLength);
    if (b.byteLength !== inputA.byteLength) {
      throw new Error(`${label}.packedB: expected ${inputA.byteLength} bytes, got ${b.byteLength}`);
    }
    return runSimpleKernel({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-packed-op-${opcode}`,
      inputA,
      inputB: b,
      outputBytes: count * byteSize,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
  }

  async function runBatch(opcode: FieldOpCode, inputA: readonly CurveGPUElementBytes[], inputB: readonly CurveGPUElementBytes[]): Promise<Uint8Array[]> {
    const count = Math.max(inputA.length, inputB.length);
    if (count === 0) {
      return [];
    }
    const a = inputA.length === 0 ? zeros(count, byteSize) : inputA;
    const b = inputB.length === 0 ? zeros(count, byteSize) : inputB;
    if (a.length !== count || b.length !== count) {
      throw new Error(`${label}: mismatched batch lengths`);
    }

    const output = await runSimpleKernel({
      device: context.device,
      kernel,
      label: `${label}-op-${opcode}`,
      inputA: packElementBatch(a, byteSize, `${label}.inputA`),
      inputB: packElementBatch(b, byteSize, `${label}.inputB`),
      outputBytes: count * byteSize,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackElementBatch(output, byteSize, count);
  }

  async function runUnary(opcode: FieldOpCode, value: CurveGPUElementBytes): Promise<Uint8Array> {
    ensureByteLength(value, byteSize, `${label}.value`);
    return (await runBatch(opcode, [value], [zeroValue]))[0];
  }

  async function runBinary(opcode: FieldOpCode, a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<Uint8Array> {
    ensureByteLength(a, byteSize, `${label}.a`);
    ensureByteLength(b, byteSize, `${label}.b`);
    return (await runBatch(opcode, [a], [b]))[0];
  }

  const getMontOne = lazyAsync(async () => cloneBytes((await runBatch(OP_ONE, [zeroValue], [zeroValue]))[0]));

  return {
    context,
    curve,
    field,
    shape,
    byteSize,
    zero(): CurveGPUElementBytes {
      return cloneBytes(zeroValue);
    },
    async copy(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runUnary(OP_COPY, value);
    },
    async copyBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_COPY, values, values);
    },
    async montOne(): Promise<CurveGPUElementBytes> {
      return cloneBytes(await getMontOne());
    },
    async equal(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<boolean> {
      return isNonZero(await runBinary(OP_EQUAL, a, b));
    },
    async equalBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<boolean[]> {
      return (await runBatch(OP_EQUAL, a, b)).map(isNonZero);
    },
    async add(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runBinary(OP_ADD, a, b);
    },
    async addBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_ADD, a, b);
    },
    async sub(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runBinary(OP_SUB, a, b);
    },
    async subBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_SUB, a, b);
    },
    async neg(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runUnary(OP_NEG, value);
    },
    async negBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_NEG, values, zeros(values.length, byteSize));
    },
    async double(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runUnary(OP_DOUBLE, value);
    },
    async doubleBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_DOUBLE, values, zeros(values.length, byteSize));
    },
    async mul(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runBinary(OP_MUL, a, b);
    },
    async mulBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_MUL, a, b);
    },
    async mulPackedMont(a: Uint8Array, b: Uint8Array): Promise<Uint8Array> {
      return runPacked(OP_MUL, a, b);
    },
    async square(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runUnary(OP_SQUARE, value);
    },
    async squareBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_SQUARE, values, zeros(values.length, byteSize));
    },
    async normalizeMont(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runUnary(OP_NORMALIZE, value);
    },
    async normalizeMontBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_NORMALIZE, values, zeros(values.length, byteSize));
    },
    async toMontgomery(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runUnary(OP_TO_MONT, value);
    },
    async toMontgomeryBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_TO_MONT, values, zeros(values.length, byteSize));
    },
    async toMontgomeryPacked(values: Uint8Array): Promise<Uint8Array> {
      return runPacked(OP_TO_MONT, values);
    },
    async fromMontgomery(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes> {
      return runUnary(OP_FROM_MONT, value);
    },
    async fromMontgomeryBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      return runBatch(OP_FROM_MONT, values, zeros(values.length, byteSize));
    },
    async fromMontgomeryPacked(values: Uint8Array): Promise<Uint8Array> {
      return runPacked(OP_FROM_MONT, values);
    },
  };
}
