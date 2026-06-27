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
const FP_QINV_NEG_16: u32 = 0xfffdu;

const FP_MODULUS16: array<u32, 24> = array<u32, 24>(
  0xaaabu, 0xffffu,
  0xffffu, 0xb9feu,
  0xffffu, 0xb153u,
  0xfffeu, 0x1eabu,
  0xf624u, 0xf6b0u,
  0xd2a0u, 0x6730u,
  0x12bfu, 0xf385u,
  0x4b84u, 0x6477u,
  0xacd7u, 0x434bu,
  0xa7b6u, 0x4b1bu,
  0xe69au, 0x397fu,
  0x11eau, 0x1a01u,
);

const FP_MODULUS_MINUS_TWO: array<u32, 12> = array<u32, 12>(
  0xffffaaa9u,
  0xb9feffffu,
  0xb153ffffu,
  0x1eabfffeu,
  0xf6b0f624u,
  0x6730d2a0u,
  0xf38512bfu,
  0x64774b84u,
  0x434bacd7u,
  0x4b1ba7b6u,
  0x397fe69au,
  0x1a0111eau,
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
  z.limbs[0] = 0x0002fffdu;
  z.limbs[1] = 0x76090000u;
  z.limbs[2] = 0xc40c0002u;
  z.limbs[3] = 0xebf4000bu;
  z.limbs[4] = 0x53c758bau;
  z.limbs[5] = 0x5f489857u;
  z.limbs[6] = 0x70525745u;
  z.limbs[7] = 0x77ce5853u;
  z.limbs[8] = 0xa256ec6du;
  z.limbs[9] = 0x5c071a97u;
  z.limbs[10] = 0xfa80e493u;
  z.limbs[11] = 0x15f65ec3u;
  return z;
}

fn fp_one_regular() -> Fp {
  var z = fp_zero();
  z.limbs[0] = 1u;
  return z;
}

fn fp_rsquare_regular() -> Fp {
  var z: Fp;
  z.limbs[0] = 0x1c341746u;
  z.limbs[1] = 0xf4df1f34u;
  z.limbs[2] = 0x09d104f1u;
  z.limbs[3] = 0x0a76e6a6u;
  z.limbs[4] = 0x4c95b6d5u;
  z.limbs[5] = 0x8de5476cu;
  z.limbs[6] = 0x939d83c0u;
  z.limbs[7] = 0x67eb88a9u;
  z.limbs[8] = 0xb519952du;
  z.limbs[9] = 0x9a793e85u;
  z.limbs[10] = 0x92cae3aau;
  z.limbs[11] = 0x11988fe5u;
  return z;
}

fn fp_modulus() -> Fp {
  var z: Fp;
  z.limbs[0] = 0xffffaaabu;
  z.limbs[1] = 0xb9feffffu;
  z.limbs[2] = 0xb153ffffu;
  z.limbs[3] = 0x1eabfffeu;
  z.limbs[4] = 0xf6b0f624u;
  z.limbs[5] = 0x6730d2a0u;
  z.limbs[6] = 0xf38512bfu;
  z.limbs[7] = 0x64774b84u;
  z.limbs[8] = 0x434bacd7u;
  z.limbs[9] = 0x4b1ba7b6u;
  z.limbs[10] = 0x397fe69au;
  z.limbs[11] = 0x1a0111eau;
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
