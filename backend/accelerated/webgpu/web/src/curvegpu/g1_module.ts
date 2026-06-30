import type {
  CurveGPUAffinePoint,
  CurveGPUContext,
  CurveGPUElementBytes,
  CurveGPUJacobianPoint,
  FieldModule,
  G1Module,
  SupportedCurveID,
} from "./api.js";
import type { SimpleKernel } from "./runtime_common.js";
import {
  cloneBytes,
  ensureByteLength,
  lazyAsync,
  runSimpleKernel,
} from "./runtime_common.js";

const OP_COPY = 0;
const OP_JAC_INFINITY = 1;
const OP_AFFINE_TO_JAC = 2;
const OP_NEG_JAC = 3;
const OP_DOUBLE_JAC = 4;
const OP_ADD_MIXED = 5;
const OP_JAC_TO_AFFINE = 6;
const OP_AFFINE_ADD = 7;

type G1OpCode =
  | typeof OP_COPY
  | typeof OP_JAC_INFINITY
  | typeof OP_AFFINE_TO_JAC
  | typeof OP_NEG_JAC
  | typeof OP_DOUBLE_JAC
  | typeof OP_ADD_MIXED
  | typeof OP_JAC_TO_AFFINE
  | typeof OP_AFFINE_ADD;

function zeroBytes(size: number): Uint8Array {
  return new Uint8Array(size);
}

function clonePoint(point: CurveGPUJacobianPoint): CurveGPUJacobianPoint {
  return { x: cloneBytes(point.x), y: cloneBytes(point.y), z: cloneBytes(point.z) };
}

function cloneAffine(point: CurveGPUAffinePoint): CurveGPUAffinePoint {
  return { x: cloneBytes(point.x), y: cloneBytes(point.y) };
}

function packJacobianPoints(points: readonly CurveGPUJacobianPoint[], coordinateBytes: number, pointBytes: number, label: string): Uint8Array {
  const out = new Uint8Array(points.length * pointBytes);
  points.forEach((point, index) => {
    ensureByteLength(point.x, coordinateBytes, `${label}[${index}].x`);
    ensureByteLength(point.y, coordinateBytes, `${label}[${index}].y`);
    ensureByteLength(point.z, coordinateBytes, `${label}[${index}].z`);
    const base = index * pointBytes;
    out.set(point.x, base);
    out.set(point.y, base + coordinateBytes);
    out.set(point.z, base + 2 * coordinateBytes);
  });
  return out;
}

function packAffinePoints(
  points: readonly CurveGPUAffinePoint[],
  coordinateBytes: number,
  pointBytes: number,
  oneMontZ: Uint8Array,
  zeroCoordinate: Uint8Array,
  label: string,
): Uint8Array {
  const out = new Uint8Array(points.length * pointBytes);
  points.forEach((point, index) => {
    ensureByteLength(point.x, coordinateBytes, `${label}[${index}].x`);
    ensureByteLength(point.y, coordinateBytes, `${label}[${index}].y`);
    const isInfinity = point.x.every((byte) => byte === 0) && point.y.every((byte) => byte === 0);
    const base = index * pointBytes;
    out.set(point.x, base);
    out.set(point.y, base + coordinateBytes);
    out.set(isInfinity ? zeroCoordinate : oneMontZ, base + 2 * coordinateBytes);
  });
  return out;
}

function unpackJacobianPoints(bytes: Uint8Array, count: number, coordinateBytes: number, pointBytes: number): CurveGPUJacobianPoint[] {
  const out: CurveGPUJacobianPoint[] = [];
  for (let i = 0; i < count; i += 1) {
    const base = i * pointBytes;
    out.push({
      x: cloneBytes(bytes.slice(base, base + coordinateBytes)),
      y: cloneBytes(bytes.slice(base + coordinateBytes, base + 2 * coordinateBytes)),
      z: cloneBytes(bytes.slice(base + 2 * coordinateBytes, base + 3 * coordinateBytes)),
    });
  }
  return out;
}

function affineFromJacobian(point: CurveGPUJacobianPoint): CurveGPUAffinePoint {
  return { x: cloneBytes(point.x), y: cloneBytes(point.y) };
}

function isAffineInfinity(point: CurveGPUAffinePoint): boolean {
  return point.x.every((byte) => byte === 0) && point.y.every((byte) => byte === 0);
}

function scalarBit(scalar: Uint8Array, bit: number): boolean {
  ensureByteLength(scalar, 32, "scalar");
  const byteIndex = Math.floor(bit / 8);
  const bitIndex = bit % 8;
  return ((scalar[byteIndex] >> bitIndex) & 1) !== 0;
}

export function createG1Module(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    coordinateBytes: number;
    pointBytes: number;
    zeroHex: string;
    kernel: SimpleKernel;
  },
  fp: FieldModule,
): G1Module {
  const { curve, coordinateBytes, pointBytes, zeroHex, kernel } = options;
  const label = `${curve}-g1`;
  const zeroCoordinate = zeroBytes(coordinateBytes);
  const zeroJacobianPoint = { x: zeroBytes(coordinateBytes), y: zeroBytes(coordinateBytes), z: zeroBytes(coordinateBytes) };
  const zeroAffinePoint = { x: zeroBytes(coordinateBytes), y: zeroBytes(coordinateBytes) };

  const getOneMontgomery = lazyAsync(async () => fp.montOne());

  async function runJacobianBatch(
    opcode: G1OpCode,
    inputA: readonly CurveGPUJacobianPoint[],
    inputB: readonly CurveGPUJacobianPoint[],
  ): Promise<CurveGPUJacobianPoint[]> {
    const count = Math.max(inputA.length, inputB.length);
    if (count === 0) {
      return [];
    }
    if (inputA.length !== count || inputB.length !== count) {
      throw new Error(`${label}: mismatched jacobian batch lengths`);
    }
    const output = await runSimpleKernel({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-op-${opcode}`,
      inputA: packJacobianPoints(inputA, coordinateBytes, pointBytes, `${label}.inputA`),
      inputB: packJacobianPoints(inputB, coordinateBytes, pointBytes, `${label}.inputB`),
      outputBytes: count * pointBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackJacobianPoints(output, count, coordinateBytes, pointBytes);
  }

  async function runMixedBatch(
    opcode: G1OpCode,
    inputA: readonly CurveGPUJacobianPoint[],
    inputB: readonly CurveGPUAffinePoint[],
  ): Promise<CurveGPUJacobianPoint[]> {
    const count = Math.max(inputA.length, inputB.length);
    if (count === 0) {
      return [];
    }
    if (inputA.length !== count || inputB.length !== count) {
      throw new Error(`${label}: mismatched mixed batch lengths`);
    }
    const oneMontZ = await getOneMontgomery();
    const output = await runSimpleKernel({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-op-${opcode}`,
      inputA: packJacobianPoints(inputA, coordinateBytes, pointBytes, `${label}.inputA`),
      inputB: packAffinePoints(inputB, coordinateBytes, pointBytes, oneMontZ, zeroCoordinate, `${label}.inputB`),
      outputBytes: count * pointBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackJacobianPoints(output, count, coordinateBytes, pointBytes);
  }

  async function runAffineInputBatch(
    opcode: G1OpCode,
    inputA: readonly CurveGPUAffinePoint[],
  ): Promise<CurveGPUJacobianPoint[]> {
    const count = inputA.length;
    if (count === 0) {
      return [];
    }
    const oneMontZ = await getOneMontgomery();
    const output = await runSimpleKernel({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-op-${opcode}`,
      inputA: packAffinePoints(inputA, coordinateBytes, pointBytes, oneMontZ, zeroCoordinate, `${label}.inputA`),
      inputB: packJacobianPoints(makeZeroJacobianBatch(count), coordinateBytes, pointBytes, `${label}.inputB`),
      outputBytes: count * pointBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackJacobianPoints(output, count, coordinateBytes, pointBytes);
  }

  async function runJacobianUnary(opcode: G1OpCode, point: CurveGPUJacobianPoint): Promise<CurveGPUJacobianPoint> {
    return (await runJacobianBatch(opcode, [point], [zeroJacobianPoint]))[0];
  }

  async function runMixedUnary(opcode: G1OpCode, point: CurveGPUJacobianPoint, affine: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint> {
    return (await runMixedBatch(opcode, [point], [affine]))[0];
  }

  async function runAffineUnary(opcode: G1OpCode, affine: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint> {
    return (await runAffineInputBatch(opcode, [affine]))[0];
  }

  function makeZeroJacobianBatch(count: number): CurveGPUJacobianPoint[] {
    return Array.from({ length: count }, () => clonePoint(zeroJacobianPoint));
  }

  return {
    context,
    curve,
    coordinateBytes,
    pointBytes,
    zeroHex,
    affineInfinity(): CurveGPUAffinePoint {
      return cloneAffine(zeroAffinePoint);
    },
    jacobianZero(): CurveGPUJacobianPoint {
      return clonePoint(zeroJacobianPoint);
    },
    async copy(point: CurveGPUJacobianPoint): Promise<CurveGPUJacobianPoint> {
      return runJacobianUnary(OP_COPY, point);
    },
    async copyBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUJacobianPoint[]> {
      return runJacobianBatch(OP_COPY, points, Array.from({ length: points.length }, () => zeroJacobianPoint));
    },
    async jacobianInfinity(): Promise<CurveGPUJacobianPoint> {
      return (await runJacobianBatch(OP_JAC_INFINITY, makeZeroJacobianBatch(1), makeZeroJacobianBatch(1)))[0];
    },
    async jacobianInfinityBatch(count: number): Promise<CurveGPUJacobianPoint[]> {
      const zeros = makeZeroJacobianBatch(count);
      return runJacobianBatch(OP_JAC_INFINITY, zeros, zeros);
    },
    async affineToJacobian(point: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint> {
      return runAffineUnary(OP_AFFINE_TO_JAC, point);
    },
    async affineToJacobianBatch(points: readonly CurveGPUAffinePoint[]): Promise<CurveGPUJacobianPoint[]> {
      return runAffineInputBatch(OP_AFFINE_TO_JAC, points);
    },
    async negJacobian(point: CurveGPUJacobianPoint): Promise<CurveGPUJacobianPoint> {
      return runJacobianUnary(OP_NEG_JAC, point);
    },
    async negJacobianBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUJacobianPoint[]> {
      return runJacobianBatch(OP_NEG_JAC, points, makeZeroJacobianBatch(points.length));
    },
    async doubleJacobian(point: CurveGPUJacobianPoint): Promise<CurveGPUJacobianPoint> {
      return runJacobianUnary(OP_DOUBLE_JAC, point);
    },
    async doubleJacobianBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUJacobianPoint[]> {
      return runJacobianBatch(OP_DOUBLE_JAC, points, makeZeroJacobianBatch(points.length));
    },
    async addMixed(point: CurveGPUJacobianPoint, affine: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint> {
      return runMixedUnary(OP_ADD_MIXED, point, affine);
    },
    async addMixedBatch(points: readonly CurveGPUJacobianPoint[], affine: readonly CurveGPUAffinePoint[]): Promise<CurveGPUJacobianPoint[]> {
      return runMixedBatch(OP_ADD_MIXED, points, affine);
    },
    async jacobianToAffine(point: CurveGPUJacobianPoint): Promise<CurveGPUAffinePoint> {
      return affineFromJacobian(await runJacobianUnary(OP_JAC_TO_AFFINE, point));
    },
    async jacobianToAffineBatch(points: readonly CurveGPUJacobianPoint[]): Promise<CurveGPUAffinePoint[]> {
      return (await runJacobianBatch(OP_JAC_TO_AFFINE, points, makeZeroJacobianBatch(points.length))).map(affineFromJacobian);
    },
    async affineAdd(a: CurveGPUAffinePoint, b: CurveGPUAffinePoint): Promise<CurveGPUJacobianPoint> {
      const left = await runAffineInputBatch(OP_AFFINE_TO_JAC, [a]);
      return (await runMixedBatch(OP_AFFINE_ADD, left, [b]))[0];
    },
    async affineAddBatch(a: readonly CurveGPUAffinePoint[], b: readonly CurveGPUAffinePoint[]): Promise<CurveGPUJacobianPoint[]> {
      const left = await runAffineInputBatch(OP_AFFINE_TO_JAC, a);
      return runMixedBatch(OP_AFFINE_ADD, left, b);
    },
    async scalarMulAffine(base: CurveGPUAffinePoint, scalar: CurveGPUElementBytes): Promise<CurveGPUJacobianPoint> {
      return (await this.scalarMulAffineBatch([base], [scalar]))[0];
    },
    async scalarMulAffineBatch(bases: readonly CurveGPUAffinePoint[], scalars: readonly CurveGPUElementBytes[]): Promise<CurveGPUJacobianPoint[]> {
      if (bases.length !== scalars.length) {
        throw new Error(`${label}: mismatched scalar-mul batch lengths`);
      }
      const zeros = makeZeroJacobianBatch(bases.length);
      let acc = await runJacobianBatch(OP_JAC_INFINITY, zeros, zeros);
      for (let bit = 255; bit >= 0; bit -= 1) {
        acc = await runJacobianBatch(OP_DOUBLE_JAC, acc, zeros);
        const activeBases = bases.map((point, index) => (scalarBit(scalars[index], bit) ? point : cloneAffine(zeroAffinePoint)));
        if (activeBases.every(isAffineInfinity)) {
          continue;
        }
        acc = await runMixedBatch(OP_ADD_MIXED, acc, activeBases);
      }
      return runJacobianBatch(OP_JAC_TO_AFFINE, acc, zeros);
    },
    async addAffine(a: CurveGPUAffinePoint, b: CurveGPUAffinePoint): Promise<CurveGPUAffinePoint> {
      return affineFromJacobian(await this.affineAdd(a, b));
    },
    async addAffineBatch(a: readonly CurveGPUAffinePoint[], b: readonly CurveGPUAffinePoint[]): Promise<CurveGPUAffinePoint[]> {
      return (await this.affineAddBatch(a, b)).map(affineFromJacobian);
    },
    async negAffine(point: CurveGPUAffinePoint): Promise<CurveGPUAffinePoint> {
      return affineFromJacobian(await this.negJacobian(await this.affineToJacobian(point)));
    },
    async negAffineBatch(points: readonly CurveGPUAffinePoint[]): Promise<CurveGPUAffinePoint[]> {
      return (await this.negJacobianBatch(await this.affineToJacobianBatch(points))).map(affineFromJacobian);
    },
    async doubleAffine(point: CurveGPUAffinePoint): Promise<CurveGPUAffinePoint> {
      return affineFromJacobian(await this.doubleJacobian(await this.affineToJacobian(point)));
    },
    async doubleAffineBatch(points: readonly CurveGPUAffinePoint[]): Promise<CurveGPUAffinePoint[]> {
      return (await this.doubleJacobianBatch(await this.affineToJacobianBatch(points))).map(affineFromJacobian);
    },
    async scalarMulAffineResult(base: CurveGPUAffinePoint, scalar: CurveGPUElementBytes): Promise<CurveGPUAffinePoint> {
      return affineFromJacobian(await this.scalarMulAffine(base, scalar));
    },
    async scalarMulAffineResultBatch(bases: readonly CurveGPUAffinePoint[], scalars: readonly CurveGPUElementBytes[]): Promise<CurveGPUAffinePoint[]> {
      return (await this.scalarMulAffineBatch(bases, scalars)).map(affineFromJacobian);
    },
  };
}
