// curvegpu:section fp-types begin
struct Fp {
  limbs: array<u32, 12>,
}

struct Fp24 {
  limbs: array<u32, 24>,
}
// curvegpu:section fp-types end

struct Params {
  count: u32,
  opcode: u32,
  _pad0: u32,
  _pad1: u32,
}

const FP_OP_COPY: u32 = 0u;
const FP_OP_ZERO: u32 = 1u;
const FP_OP_ONE: u32 = 2u;
const FP_OP_ADD: u32 = 3u;
const FP_OP_SUB: u32 = 4u;
const FP_OP_NEG: u32 = 5u;
const FP_OP_DOUBLE: u32 = 6u;
const FP_OP_NORMALIZE: u32 = 7u;
const FP_OP_EQUAL: u32 = 8u;
const FP_OP_MUL: u32 = 9u;
const FP_OP_SQUARE: u32 = 10u;
const FP_OP_TO_MONT: u32 = 11u;
const FP_OP_FROM_MONT: u32 = 12u;

// curvegpu:section fp-consts begin
const FP_LIMB16_MASK: u32 = 0xffffu;
const FP_QINV_NEG_16: u32 = 0xffffu;

const FP_MODULUS16: array<u32, 24> = array<u32, 24>(
  0x0001u, 0x0000u,
  0xc000u, 0x8508u,
  0x0000u, 0x3000u,
  0x5d44u, 0x170bu,
  0x4800u, 0xba09u,
  0x622fu, 0x1ef3u,
  0x138fu, 0x00f5u,
  0xd9f3u, 0x1a22u,
  0x493bu, 0x6ca1u,
  0x05c0u, 0xc63bu,
  0x10eau, 0x17c5u,
  0x3a46u, 0x01aeu,
);

const FP_MODULUS_MINUS_TWO: array<u32, 12> = array<u32, 12>(
  0xffffffffu,
  0x8508bfffu,
  0x30000000u,
  0x170b5d44u,
  0xba094800u,
  0x1ef3622fu,
  0x00f5138fu,
  0x1a22d9f3u,
  0x6ca1493bu,
  0xc63b05c0u,
  0x17c510eau,
  0x01ae3a46u,
);
// curvegpu:section fp-consts end

@group(0) @binding(0) var<storage, read> input_a: array<u32>;
@group(0) @binding(1) var<storage, read> input_b: array<u32>;
@group(0) @binding(2) var<storage, read_write> output: array<u32>;
@group(0) @binding(3) var<uniform> params: Params;

// curvegpu:section fp-core begin
fn fp_zero() -> Fp {
  var z: Fp;
  for (var i = 0u; i < 12u; i = i + 1u) {
    z.limbs[i] = 0u;
  }
  return z;
}

fn fp_one() -> Fp {
  var z: Fp;
  z.limbs[0] = 0xffffff68u;
  z.limbs[1] = 0x02cdffffu;
  z.limbs[2] = 0x7fffffb1u;
  z.limbs[3] = 0x51409f83u;
  z.limbs[4] = 0x8a7d3ff2u;
  z.limbs[5] = 0x9f7db3a9u;
  z.limbs[6] = 0x6e7c6305u;
  z.limbs[7] = 0x7b4e97b7u;
  z.limbs[8] = 0x803c84e8u;
  z.limbs[9] = 0x4cf495bfu;
  z.limbs[10] = 0xe2fdf49au;
  z.limbs[11] = 0x008d6661u;
  return z;
}

fn fp_one_regular() -> Fp {
  var z = fp_zero();
  z.limbs[0] = 1u;
  return z;
}

fn fp_rsquare_regular() -> Fp {
  var z: Fp;
  z.limbs[0] = 0x9400cd22u;
  z.limbs[1] = 0xb786686cu;
  z.limbs[2] = 0xb00431b1u;
  z.limbs[3] = 0x0329fcaau;
  z.limbs[4] = 0x62d6b46du;
  z.limbs[5] = 0x22a5f111u;
  z.limbs[6] = 0x827dc3acu;
  z.limbs[7] = 0xbfdf7d03u;
  z.limbs[8] = 0x41790bf9u;
  z.limbs[9] = 0x837e92f0u;
  z.limbs[10] = 0x1e914b88u;
  z.limbs[11] = 0x006dfccbu;
  return z;
}

fn fp_modulus() -> Fp {
  var z: Fp;
  z.limbs[0] = 0x00000001u;
  z.limbs[1] = 0x8508c000u;
  z.limbs[2] = 0x30000000u;
  z.limbs[3] = 0x170b5d44u;
  z.limbs[4] = 0xba094800u;
  z.limbs[5] = 0x1ef3622fu;
  z.limbs[6] = 0x00f5138fu;
  z.limbs[7] = 0x1a22d9f3u;
  z.limbs[8] = 0x6ca1493bu;
  z.limbs[9] = 0xc63b05c0u;
  z.limbs[10] = 0x17c510eau;
  z.limbs[11] = 0x01ae3a46u;
  return z;
}

fn fp_predicate(value: bool) -> Fp {
  var z = fp_zero();
  if (value) {
    z = fp_one();
  }
  return z;
}

fn adc(a: u32, b: u32, carry: u32) -> vec2<u32> {
  let sum0 = a + b;
  let carry0 = select(0u, 1u, sum0 < a);
  let sum1 = sum0 + carry;
  let carry1 = select(0u, 1u, sum1 < sum0);
  return vec2<u32>(sum1, carry0 | carry1);
}

fn sbb(a: u32, b: u32, borrow: u32) -> vec2<u32> {
  let diff0 = a - b;
  let borrow0 = select(0u, 1u, a < b);
  let diff1 = diff0 - borrow;
  let borrow1 = select(0u, 1u, diff1 > diff0);
  return vec2<u32>(diff1, borrow0 | borrow1);
}

fn fp_is_zero(x: Fp) -> bool {
  var acc = 0u;
  for (var i = 0u; i < 12u; i = i + 1u) {
    let limb = x.limbs[i];
    acc = acc | limb;
  }
  return acc == 0u;
}

fn fp_equal(x: Fp, y: Fp) -> bool {
  for (var i = 0u; i < 12u; i = i + 1u) {
    let xLimb = x.limbs[i];
    let yLimb = y.limbs[i];
    if (xLimb != yLimb) {
      return false;
    }
  }
  return true;
}

fn fp_gte(x: Fp, y: Fp) -> bool {
  for (var i: i32 = 11; i >= 0; i = i - 1) {
    let idx = u32(i);
    let xLimb = x.limbs[idx];
    let yLimb = y.limbs[idx];
    if (xLimb != yLimb) {
      return xLimb > yLimb;
    }
  }
  return true;
}

fn fp_add_modulus(x: Fp) -> Fp {
  let q = fp_modulus();
  var z: Fp;
  var carry = 0u;
  for (var i = 0u; i < 12u; i = i + 1u) {
    let lane = adc(x.limbs[i], q.limbs[i], carry);
    z.limbs[i] = lane.x;
    carry = lane.y;
  }
  return z;
}

fn fp_sub_modulus(x: Fp) -> Fp {
  let q = fp_modulus();
  var z: Fp;
  var borrow = 0u;
  for (var i = 0u; i < 12u; i = i + 1u) {
    let lane = sbb(x.limbs[i], q.limbs[i], borrow);
    z.limbs[i] = lane.x;
    borrow = lane.y;
  }
  return z;
}

fn fp_add(x: Fp, y: Fp) -> Fp {
  var z: Fp;
  var carry = 0u;
  for (var i = 0u; i < 12u; i = i + 1u) {
    let lane = adc(x.limbs[i], y.limbs[i], carry);
    z.limbs[i] = lane.x;
    carry = lane.y;
  }
  if ((carry != 0u) || fp_gte(z, fp_modulus())) {
    return fp_sub_modulus(z);
  }
  return z;
}

fn fp_sub(x: Fp, y: Fp) -> Fp {
  var z: Fp;
  var borrow = 0u;
  for (var i = 0u; i < 12u; i = i + 1u) {
    let lane = sbb(x.limbs[i], y.limbs[i], borrow);
    z.limbs[i] = lane.x;
    borrow = lane.y;
  }
  if (borrow != 0u) {
    return fp_add_modulus(z);
  }
  return z;
}

fn fp_neg(x: Fp) -> Fp {
  if (fp_is_zero(x)) {
    return fp_zero();
  }
  return fp_sub(fp_modulus(), x);
}

fn fp_double(x: Fp) -> Fp {
  return fp_add(x, x);
}

fn fp_normalize(x: Fp) -> Fp {
  if (fp_gte(x, fp_modulus())) {
    return fp_sub_modulus(x);
  }
  return x;
}

fn fp_unpack16(x: Fp) -> Fp24 {
  var z: Fp24;
  for (var i = 0u; i < 12u; i = i + 1u) {
    z.limbs[2u * i] = x.limbs[i] & FP_LIMB16_MASK;
    z.limbs[2u * i + 1u] = x.limbs[i] >> 16u;
  }
  return z;
}

fn fp_pack16(x: Fp24) -> Fp {
  var z: Fp;
  for (var i = 0u; i < 12u; i = i + 1u) {
    z.limbs[i] = x.limbs[2u * i] | (x.limbs[2u * i + 1u] << 16u);
  }
  return z;
}

fn fp24_gte_modulus(x: Fp24) -> bool {
  for (var i: i32 = 23; i >= 0; i = i - 1) {
    let idx = u32(i);
    let xLimb = x.limbs[idx];
    let qLimb = FP_MODULUS16[idx];
    if (xLimb != qLimb) {
      return xLimb > qLimb;
    }
  }
  return true;
}

fn fp24_sub_modulus(x: Fp24) -> Fp24 {
  var z: Fp24;
  var borrow = 0u;
  for (var i = 0u; i < 24u; i = i + 1u) {
    let lane = sbb(x.limbs[i], FP_MODULUS16[i], borrow);
    z.limbs[i] = lane.x & FP_LIMB16_MASK;
    borrow = lane.y;
  }
  return z;
}

fn fp_mul(x: Fp, y: Fp) -> Fp {
  let a = fp_unpack16(x);
  let b = fp_unpack16(y);
  var t: array<u32, 25>;

  for (var i = 0u; i < 24u; i = i + 1u) {
    var carry = 0u;
    let bi = b.limbs[i];
    for (var j = 0u; j < 24u; j = j + 1u) {
      let aLimb = a.limbs[j];
      let uv = t[j] + (aLimb * bi) + carry;
      t[j] = uv & FP_LIMB16_MASK;
      carry = uv >> 16u;
    }
    t[24] = carry;

    let m = (t[0] * FP_QINV_NEG_16) & FP_LIMB16_MASK;
    carry = 0u;
    for (var j = 0u; j < 24u; j = j + 1u) {
      let qLimb = FP_MODULUS16[j];
      let uv = t[j] + (m * qLimb) + carry;
      if (j > 0u) {
        t[j - 1u] = uv & FP_LIMB16_MASK;
      }
      carry = uv >> 16u;
    }
    let uv = t[24] + carry;
    t[23] = uv & FP_LIMB16_MASK;
    t[24] = uv >> 16u;
  }

  var z24: Fp24;
  for (var i = 0u; i < 24u; i = i + 1u) {
    z24.limbs[i] = t[i];
  }
  if ((t[24] != 0u) || fp24_gte_modulus(z24)) {
    z24 = fp24_sub_modulus(z24);
  }
  return fp_pack16(z24);
}

fn fp_square(x: Fp) -> Fp {
  return fp_mul(x, x);
}

fn fp_inverse(x: Fp) -> Fp {
  if (fp_is_zero(x)) {
    return fp_zero();
  }
  var acc = fp_one();
  for (var word_index: i32 = 11; word_index >= 0; word_index = word_index - 1) {
    let word = FP_MODULUS_MINUS_TWO[u32(word_index)];
    for (var bit_index: i32 = 31; bit_index >= 0; bit_index = bit_index - 1) {
      acc = fp_square(acc);
      if (((word >> u32(bit_index)) & 1u) != 0u) {
        acc = fp_mul(acc, x);
      }
    }
  }
  return acc;
}
// curvegpu:section fp-core end

fn fp_dispatch(opcode: u32, a: Fp, b: Fp) -> Fp {
  if (opcode == FP_OP_COPY) {
    return a;
  }
  if (opcode == FP_OP_ZERO) {
    return fp_zero();
  }
  if (opcode == FP_OP_ONE) {
    return fp_one();
  }
  if (opcode == FP_OP_ADD) {
    return fp_add(a, b);
  }
  if (opcode == FP_OP_SUB) {
    return fp_sub(a, b);
  }
  if (opcode == FP_OP_NEG) {
    return fp_neg(a);
  }
  if (opcode == FP_OP_DOUBLE) {
    return fp_double(a);
  }
  if (opcode == FP_OP_NORMALIZE) {
    return fp_normalize(a);
  }
  if (opcode == FP_OP_EQUAL) {
    return fp_predicate(fp_equal(a, b));
  }
  if (opcode == FP_OP_MUL) {
    return fp_mul(a, b);
  }
  if (opcode == FP_OP_SQUARE) {
    return fp_square(a);
  }
  if (opcode == FP_OP_TO_MONT) {
    return fp_mul(a, fp_rsquare_regular());
  }
  if (opcode == FP_OP_FROM_MONT) {
    return fp_mul(a, fp_one_regular());
  }
  return fp_zero();
}

fn fp_load_a(index: u32) -> Fp {
  let base = index * 12u;
  var z: Fp;
  for (var i = 0u; i < 12u; i = i + 1u) {
    z.limbs[i] = input_a[base + i];
  }
  return z;
}

fn fp_load_b(index: u32) -> Fp {
  let base = index * 12u;
  var z: Fp;
  for (var i = 0u; i < 12u; i = i + 1u) {
    z.limbs[i] = input_b[base + i];
  }
  return z;
}

fn fp_store(index: u32, value: Fp) {
  let base = index * 12u;
  for (var i = 0u; i < 12u; i = i + 1u) {
    output[base + i] = value.limbs[i];
  }
}

override WORKGROUP_SIZE: u32 = 64;

@compute @workgroup_size(WORKGROUP_SIZE)
fn fp_ops_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params.count) {
    return;
  }
  fp_store(i, fp_dispatch(params.opcode, fp_load_a(i), fp_load_b(i)));
}
