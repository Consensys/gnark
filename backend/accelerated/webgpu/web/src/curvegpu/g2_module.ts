import type {
  CurveGPUContext,
  CurveGPUFp2Element,
  CurveGPUG2AffinePoint,
  CurveGPUG2JacobianPoint,
  FieldModule,
  G2Module,
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

type G2OpCode =
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

function zeroFp2(size: number): CurveGPUFp2Element {
  return { c0: zeroBytes(size), c1: zeroBytes(size) };
}

function cloneFp2(value: CurveGPUFp2Element): CurveGPUFp2Element {
  return { c0: cloneBytes(value.c0), c1: cloneBytes(value.c1) };
}

function cloneJacobian(point: CurveGPUG2JacobianPoint): CurveGPUG2JacobianPoint {
  return {
    x: cloneFp2(point.x),
    y: cloneFp2(point.y),
    z: cloneFp2(point.z),
  };
}

function cloneAffine(point: CurveGPUG2AffinePoint): CurveGPUG2AffinePoint {
  return {
    x: cloneFp2(point.x),
    y: cloneFp2(point.y),
  };
}

function ensureFp2(value: CurveGPUFp2Element, componentBytes: number, label: string): void {
  ensureByteLength(value.c0, componentBytes, `${label}.c0`);
  ensureByteLength(value.c1, componentBytes, `${label}.c1`);
}

function fp2IsZero(value: CurveGPUFp2Element): boolean {
  return value.c0.every((byte) => byte === 0) && value.c1.every((byte) => byte === 0);
}

function isAffineInfinity(point: CurveGPUG2AffinePoint): boolean {
  return fp2IsZero(point.x) && fp2IsZero(point.y);
}

function scalarBit(scalar: Uint8Array, bit: number): boolean {
  ensureByteLength(scalar, 32, "scalar");
  const byteIndex = Math.floor(bit / 8);
  const bitIndex = bit % 8;
  return ((scalar[byteIndex] >> bitIndex) & 1) !== 0;
}

function packFp2(out: Uint8Array, offset: number, value: CurveGPUFp2Element): void {
  out.set(value.c0, offset);
  out.set(value.c1, offset + value.c0.byteLength);
}

function packJacobianPoints(
  points: readonly CurveGPUG2JacobianPoint[],
  componentBytes: number,
  pointBytes: number,
  label: string,
): Uint8Array {
  const out = new Uint8Array(points.length * pointBytes);
  points.forEach((point, index) => {
    ensureFp2(point.x, componentBytes, `${label}[${index}].x`);
    ensureFp2(point.y, componentBytes, `${label}[${index}].y`);
    ensureFp2(point.z, componentBytes, `${label}[${index}].z`);
    const base = index * pointBytes;
    packFp2(out, base, point.x);
    packFp2(out, base + 2 * componentBytes, point.y);
    packFp2(out, base + 4 * componentBytes, point.z);
  });
  return out;
}

function packAffinePoints(
  points: readonly CurveGPUG2AffinePoint[],
  componentBytes: number,
  pointBytes: number,
  oneMontZ: CurveGPUFp2Element,
  zeroCoordinate: CurveGPUFp2Element,
  label: string,
): Uint8Array {
  const out = new Uint8Array(points.length * pointBytes);
  points.forEach((point, index) => {
    ensureFp2(point.x, componentBytes, `${label}[${index}].x`);
    ensureFp2(point.y, componentBytes, `${label}[${index}].y`);
    const isInfinity = fp2IsZero(point.x) && fp2IsZero(point.y);
    const base = index * pointBytes;
    packFp2(out, base, point.x);
    packFp2(out, base + 2 * componentBytes, point.y);
    packFp2(out, base + 4 * componentBytes, isInfinity ? zeroCoordinate : oneMontZ);
  });
  return out;
}

function unpackFp2(bytes: Uint8Array, offset: number, componentBytes: number): CurveGPUFp2Element {
  return {
    c0: cloneBytes(bytes.slice(offset, offset + componentBytes)),
    c1: cloneBytes(bytes.slice(offset + componentBytes, offset + 2 * componentBytes)),
  };
}

function unpackJacobianPoints(
  bytes: Uint8Array,
  count: number,
  componentBytes: number,
  pointBytes: number,
): CurveGPUG2JacobianPoint[] {
  const out: CurveGPUG2JacobianPoint[] = [];
  for (let i = 0; i < count; i += 1) {
    const base = i * pointBytes;
    out.push({
      x: unpackFp2(bytes, base, componentBytes),
      y: unpackFp2(bytes, base + 2 * componentBytes, componentBytes),
      z: unpackFp2(bytes, base + 4 * componentBytes, componentBytes),
    });
  }
  return out;
}

function affineFromJacobian(point: CurveGPUG2JacobianPoint): CurveGPUG2AffinePoint {
  return {
    x: cloneFp2(point.x),
    y: cloneFp2(point.y),
  };
}

export function createG2Module(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    componentBytes: number;
    coordinateBytes: number;
    pointBytes: number;
    kernel: SimpleKernel;
  },
  fp: FieldModule,
): G2Module {
  const { curve, componentBytes, coordinateBytes, pointBytes, kernel } = options;
  const label = `${curve}-g2`;

  const zeroCoordinate = zeroFp2(componentBytes);
  const zeroJacobianPoint: CurveGPUG2JacobianPoint = {
    x: zeroFp2(componentBytes),
    y: zeroFp2(componentBytes),
    z: zeroFp2(componentBytes),
  };
  const zeroAffinePoint: CurveGPUG2AffinePoint = {
    x: zeroFp2(componentBytes),
    y: zeroFp2(componentBytes),
  };

  const getOneMontgomery = lazyAsync(async () => {
    const c0 = await fp.montOne();
    const c1 = zeroBytes(componentBytes);
    return { c0, c1 };
  });

  function makeZeroJacobianBatch(count: number): CurveGPUG2JacobianPoint[] {
    return Array.from({ length: count }, () => cloneJacobian(zeroJacobianPoint));
  }

  async function runJacobianBatch(
    opcode: G2OpCode,
    inputA: readonly CurveGPUG2JacobianPoint[],
    inputB: readonly CurveGPUG2JacobianPoint[],
  ): Promise<CurveGPUG2JacobianPoint[]> {
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
      inputA: packJacobianPoints(inputA, componentBytes, pointBytes, `${label}.inputA`),
      inputB: packJacobianPoints(inputB, componentBytes, pointBytes, `${label}.inputB`),
      outputBytes: count * pointBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackJacobianPoints(output, count, componentBytes, pointBytes);
  }

  async function runMixedBatch(
    opcode: G2OpCode,
    inputA: readonly CurveGPUG2JacobianPoint[],
    inputB: readonly CurveGPUG2AffinePoint[],
  ): Promise<CurveGPUG2JacobianPoint[]> {
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
      inputA: packJacobianPoints(inputA, componentBytes, pointBytes, `${label}.inputA`),
      inputB: packAffinePoints(inputB, componentBytes, pointBytes, oneMontZ, zeroCoordinate, `${label}.inputB`),
      outputBytes: count * pointBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackJacobianPoints(output, count, componentBytes, pointBytes);
  }

  async function runAffineInputBatch(
    opcode: G2OpCode,
    inputA: readonly CurveGPUG2AffinePoint[],
  ): Promise<CurveGPUG2JacobianPoint[]> {
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
      inputA: packAffinePoints(inputA, componentBytes, pointBytes, oneMontZ, zeroCoordinate, `${label}.inputA`),
      inputB: packJacobianPoints(makeZeroJacobianBatch(count), componentBytes, pointBytes, `${label}.inputB`),
      outputBytes: count * pointBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackJacobianPoints(output, count, componentBytes, pointBytes);
  }

  async function runJacobianUnary(opcode: G2OpCode, point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2JacobianPoint> {
    return (await runJacobianBatch(opcode, [point], [zeroJacobianPoint]))[0];
  }

  async function runMixedUnary(opcode: G2OpCode, point: CurveGPUG2JacobianPoint, affine: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint> {
    return (await runMixedBatch(opcode, [point], [affine]))[0];
  }

  async function runAffineUnary(opcode: G2OpCode, affine: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint> {
    return (await runAffineInputBatch(opcode, [affine]))[0];
  }

  return {
    context,
    curve,
    componentBytes,
    coordinateBytes,
    pointBytes,
    affineInfinity(): CurveGPUG2AffinePoint {
      return cloneAffine(zeroAffinePoint);
    },
    jacobianZero(): CurveGPUG2JacobianPoint {
      return cloneJacobian(zeroJacobianPoint);
    },
    async copy(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2JacobianPoint> {
      return runJacobianUnary(OP_COPY, point);
    },
    async copyBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2JacobianPoint[]> {
      return runJacobianBatch(OP_COPY, points, Array.from({ length: points.length }, () => zeroJacobianPoint));
    },
    async jacobianInfinity(): Promise<CurveGPUG2JacobianPoint> {
      return (await runJacobianBatch(OP_JAC_INFINITY, makeZeroJacobianBatch(1), makeZeroJacobianBatch(1)))[0];
    },
    async jacobianInfinityBatch(count: number): Promise<CurveGPUG2JacobianPoint[]> {
      const zeros = makeZeroJacobianBatch(count);
      return runJacobianBatch(OP_JAC_INFINITY, zeros, zeros);
    },
    async affineToJacobian(point: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint> {
      return runAffineUnary(OP_AFFINE_TO_JAC, point);
    },
    async affineToJacobianBatch(points: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2JacobianPoint[]> {
      return runAffineInputBatch(OP_AFFINE_TO_JAC, points);
    },
    async negJacobian(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2JacobianPoint> {
      return runJacobianUnary(OP_NEG_JAC, point);
    },
    async negJacobianBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2JacobianPoint[]> {
      return runJacobianBatch(OP_NEG_JAC, points, Array.from({ length: points.length }, () => zeroJacobianPoint));
    },
    async doubleJacobian(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2JacobianPoint> {
      return runJacobianUnary(OP_DOUBLE_JAC, point);
    },
    async doubleJacobianBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2JacobianPoint[]> {
      return runJacobianBatch(OP_DOUBLE_JAC, points, Array.from({ length: points.length }, () => zeroJacobianPoint));
    },
    async addMixed(point: CurveGPUG2JacobianPoint, affine: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint> {
      return runMixedUnary(OP_ADD_MIXED, point, affine);
    },
    async addMixedBatch(
      points: readonly CurveGPUG2JacobianPoint[],
      affine: readonly CurveGPUG2AffinePoint[],
    ): Promise<CurveGPUG2JacobianPoint[]> {
      return runMixedBatch(OP_ADD_MIXED, points, affine);
    },
    async jacobianToAffine(point: CurveGPUG2JacobianPoint): Promise<CurveGPUG2AffinePoint> {
      return affineFromJacobian((await runJacobianBatch(OP_JAC_TO_AFFINE, [point], [zeroJacobianPoint]))[0]);
    },
    async jacobianToAffineBatch(points: readonly CurveGPUG2JacobianPoint[]): Promise<CurveGPUG2AffinePoint[]> {
      return (await runJacobianBatch(OP_JAC_TO_AFFINE, points, Array.from({ length: points.length }, () => zeroJacobianPoint))).map(affineFromJacobian);
    },
    async affineAdd(a: CurveGPUG2AffinePoint, b: CurveGPUG2AffinePoint): Promise<CurveGPUG2JacobianPoint> {
      const left = await runAffineInputBatch(OP_AFFINE_TO_JAC, [a]);
      return (await runMixedBatch(OP_AFFINE_ADD, left, [b]))[0];
    },
    async affineAddBatch(a: readonly CurveGPUG2AffinePoint[], b: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2JacobianPoint[]> {
      if (a.length !== b.length) {
        throw new Error(`${label}: mismatched affine batch lengths`);
      }
      const left = await runAffineInputBatch(OP_AFFINE_TO_JAC, a);
      return runMixedBatch(OP_AFFINE_ADD, left, b);
    },
    async scalarMulAffine(base: CurveGPUG2AffinePoint, scalar: Uint8Array): Promise<CurveGPUG2JacobianPoint> {
      return (await this.scalarMulAffineBatch([base], [scalar]))[0];
    },
    async scalarMulAffineBatch(
      bases: readonly CurveGPUG2AffinePoint[],
      scalars: readonly Uint8Array[],
    ): Promise<CurveGPUG2JacobianPoint[]> {
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
    async addAffine(a: CurveGPUG2AffinePoint, b: CurveGPUG2AffinePoint): Promise<CurveGPUG2AffinePoint> {
      return affineFromJacobian(await this.affineAdd(a, b));
    },
    async addAffineBatch(a: readonly CurveGPUG2AffinePoint[], b: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2AffinePoint[]> {
      return (await this.affineAddBatch(a, b)).map(affineFromJacobian);
    },
    async negAffine(point: CurveGPUG2AffinePoint): Promise<CurveGPUG2AffinePoint> {
      return affineFromJacobian(await this.negJacobian(await this.affineToJacobian(point)));
    },
    async negAffineBatch(points: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2AffinePoint[]> {
      return (await this.negJacobianBatch(await this.affineToJacobianBatch(points))).map(affineFromJacobian);
    },
    async doubleAffine(point: CurveGPUG2AffinePoint): Promise<CurveGPUG2AffinePoint> {
      return affineFromJacobian(await this.doubleJacobian(await this.affineToJacobian(point)));
    },
    async doubleAffineBatch(points: readonly CurveGPUG2AffinePoint[]): Promise<CurveGPUG2AffinePoint[]> {
      return (await this.doubleJacobianBatch(await this.affineToJacobianBatch(points))).map(affineFromJacobian);
    },
    async scalarMulAffineResult(base: CurveGPUG2AffinePoint, scalar: Uint8Array): Promise<CurveGPUG2AffinePoint> {
      return affineFromJacobian(await this.scalarMulAffine(base, scalar));
    },
    async scalarMulAffineResultBatch(bases: readonly CurveGPUG2AffinePoint[], scalars: readonly Uint8Array[]): Promise<CurveGPUG2AffinePoint[]> {
      return (await this.scalarMulAffineBatch(bases, scalars)).map(affineFromJacobian);
    },
  };
}
