var<workgroup> g1_jac_wg: array<G1Point, 64>;

// Bucket accumulation: sparse signed bases → Jacobian bucket sums (no g1_jac_to_affine).
@compute @workgroup_size(64)
fn g1_msm_bucket_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) { return; }
  let start = input_meta1[i];
  let size = input_meta2[i];
  var acc = g1_jac_infinity();
  for (var j = 0u; j < size; j = j + 1u) {
    let raw = input_meta0[start + j];
    let idx = raw & 0x7fffffffu;
    let neg = (raw & 0x80000000u) != 0u;
    var point = g1_load_from(0u, idx);
    if (neg) { point = g1_neg_affine(point); }
    acc = g1_add_mixed(acc, point);
  }
  g1_store(i, acc);
}

// Weight buckets: multiply each Jacobian bucket sum by its bucket index.
@compute @workgroup_size(64)
fn g1_msm_weight_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) { return; }
  let point = g1_load_from(0u, i);
  let value = input_meta0[i];
  if (g1_jac_is_infinity(point) || value == 0u) {
    g1_store(i, g1_jac_infinity());
    return;
  }
  g1_store(i, g1_scalar_mul_jac_small(point, value));
}

// Subsum: reduce weighted Jacobian buckets into one Jacobian sum per window.
// One workgroup per window; 64 threads stride + internal tree reduction.
@compute @workgroup_size(64)
fn g1_msm_subsum_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  if (i >= params_count()) { return; }
  let start = input_meta1[i];
  let count = input_meta2[i];
  var local_sum = g1_jac_infinity();
  var j = tid;
  loop {
    if (j >= count) { break; }
    let point = g1_load_from(0u, start + j);
    if (!g1_jac_is_infinity(point)) {
      local_sum = g1_add_jac(local_sum, point);
    }
    j = j + 64u;
  }
  g1_jac_wg[tid] = local_sum;
  workgroupBarrier();

  var stride = 32u;
  loop {
    if (stride == 0u) { break; }
    if (tid < stride) {
      g1_jac_wg[tid] = g1_add_jac(g1_jac_wg[tid], g1_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }
  if (tid == 0u) {
    g1_store(i, g1_jac_wg[0u]);
  }
}

// Combine: Horner evaluation over Jacobian window sums. One g1_jac_to_affine per instance.
@compute @workgroup_size(64)
fn g1_msm_combine_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) { return; }
  let num_windows = params_num_windows();
  let window = params_window();
  var acc = g1_jac_infinity();
  for (var win: i32 = i32(num_windows) - 1; win >= 0; win = win - 1) {
    if (u32(win) != (num_windows - 1u)) {
      for (var step = 0u; step < window; step = step + 1u) {
        acc = g1_double_jac(acc);
      }
    }
    let point = g1_load_from(0u, i * num_windows + u32(win));
    if (g1_jac_is_infinity(point)) { continue; }
    acc = g1_add_jac(acc, point);
  }
  g1_store(i, g1_jac_to_affine(acc));
}
