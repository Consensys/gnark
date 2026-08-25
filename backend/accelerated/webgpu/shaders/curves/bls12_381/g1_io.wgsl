fn fp_load_from(buffer_kind: u32, base: u32) -> Fp {
  var z: Fp;
  if (buffer_kind == 0u) {
    for (var i = 0u; i < 12u; i = i + 1u) {
      z.limbs[i] = input_a[base + i];
    }
    return z;
  }
  for (var i = 0u; i < 12u; i = i + 1u) {
    z.limbs[i] = input_b[base + i];
  }
  return z;
}

fn g1_load_from(buffer_kind: u32, index: u32) -> G1Point {
  let base = index * 36u;
  var p: G1Point;
  p.x = fp_load_from(buffer_kind, base + 0u);
  p.y = fp_load_from(buffer_kind, base + 12u);
  p.z = fp_load_from(buffer_kind, base + 24u);
  return p;
}

fn fp_store(base: u32, value: Fp) {
  for (var i = 0u; i < 12u; i = i + 1u) {
    output[base + i] = value.limbs[i];
  }
}

fn g1_store(index: u32, value: G1Point) {
  let base = index * 36u;
  fp_store(base + 0u, value.x);
  fp_store(base + 12u, value.y);
  fp_store(base + 24u, value.z);
}
