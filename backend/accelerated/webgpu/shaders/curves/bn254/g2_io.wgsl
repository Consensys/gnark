fn fp_load_from(buffer_kind: u32, base: u32) -> Fp {
  var z: Fp;
  if (buffer_kind == 0u) {
    for (var i = 0u; i < 8u; i = i + 1u) {
      z.limbs[i] = input_a[base + i];
    }
    return z;
  }
  for (var i = 0u; i < 8u; i = i + 1u) {
    z.limbs[i] = input_b[base + i];
  }
  return z;
}

fn fp2_load_from(buffer_kind: u32, base: u32) -> Fp2 {
  var z: Fp2;
  z.c0 = fp_load_from(buffer_kind, base);
  z.c1 = fp_load_from(buffer_kind, base + 8u);
  return z;
}

fn g2_load_from(buffer_kind: u32, index: u32) -> G2Point {
  let base = index * 48u;
  var p: G2Point;
  p.x = fp2_load_from(buffer_kind, base + 0u);
  p.y = fp2_load_from(buffer_kind, base + 16u);
  p.z = fp2_load_from(buffer_kind, base + 32u);
  return p;
}

fn fp_store(base: u32, value: Fp) {
  for (var i = 0u; i < 8u; i = i + 1u) {
    output[base + i] = value.limbs[i];
  }
}

fn fp2_store(base: u32, value: Fp2) {
  fp_store(base, value.c0);
  fp_store(base + 8u, value.c1);
}

fn g2_store(index: u32, value: G2Point) {
  let base = index * 48u;
  fp2_store(base + 0u, value.x);
  fp2_store(base + 16u, value.y);
  fp2_store(base + 32u, value.z);
}
