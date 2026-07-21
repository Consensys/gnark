var<workgroup> g2_jac_wg: array<G2Point, 32>;

fn msm_jac_params_window() -> u32 {
  return params.lane0.w;
}

fn msm_jac_params_num_windows() -> u32 {
  return params.lane1.x;
}

// Bucket accumulation: sparse signed base list → Jacobian bucket sums.
// Bases in input_a are stored as Jacobian with z=1 (affine encoding).
// Output stored as Jacobian (no g2_jac_to_affine inversion).
@compute @workgroup_size(32)
fn g2_msm_bucket_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) {
    return;
  }
  let start = input_meta1[i];
  let size = input_meta2[i];
  var acc = g2_jac_infinity();
  for (var j = 0u; j < size; j = j + 1u) {
    let raw = input_meta0[start + j];
    let idx = raw & 0x7fffffffu;
    let neg = (raw & 0x80000000u) != 0u;
    var point = g2_load_from(0u, idx);
    if (neg) {
      point = g2_neg_affine(point);
    }
    acc = g2_add_mixed(acc, point);
  }
  g2_store(i, acc);
}

// Weight buckets: multiply each Jacobian bucket sum by its scalar bucket index.
// Input (input_a) and output are Jacobian. No inversions.
@compute @workgroup_size(32)
fn g2_msm_weight_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) {
    return;
  }
  let point = g2_load_from(0u, i);
  let value = input_meta0[i];
  if (g2_jac_is_infinity(point) || value == 0u) {
    g2_store(i, g2_jac_infinity());
    return;
  }
  g2_store(i, g2_scalar_mul_jac_small(point, value));
}

// Subsum: reduce weighted Jacobian bucket sums into one Jacobian sum per window.
// One workgroup per window. 32 threads stride through the window's bucket range,
// then a tree reduction collapses 32 partial sums into one.
@compute @workgroup_size(32)
fn g2_msm_subsum_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  if (i >= params_count()) {
    return;
  }
  let start = input_meta1[i];
  let count = input_meta2[i];

  // Each thread accumulates its strided portion of the window's buckets.
  var local_sum = g2_jac_infinity();
  var j = tid;
  loop {
    if (j >= count) {
      break;
    }
    let point = g2_load_from(0u, start + j);
    if (!g2_jac_is_infinity(point)) {
      local_sum = g2_add_jac(local_sum, point);
    }
    j = j + 32u;
  }

  g2_jac_wg[tid] = local_sum;
  workgroupBarrier();

  // Tree reduction over 32 partial sums.
  var stride = 16u;
  loop {
    if (stride == 0u) {
      break;
    }
    if (tid < stride) {
      g2_jac_wg[tid] = g2_add_jac(g2_jac_wg[tid], g2_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }

  if (tid == 0u) {
    g2_store(i, g2_jac_wg[0u]);
  }
}

// Combine: Horner evaluation over window sums → single MSM result per instance.
// Reads Jacobian window sums. Performs one g2_jac_to_affine per instance.
@compute @workgroup_size(32)
fn g2_msm_combine_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) {
    return;
  }
  let num_windows = msm_jac_params_num_windows();
  let window = msm_jac_params_window();
  var acc = g2_jac_infinity();
  for (var win: i32 = i32(num_windows) - 1; win >= 0; win = win - 1) {
    if (u32(win) != (num_windows - 1u)) {
      for (var step = 0u; step < window; step = step + 1u) {
        acc = g2_double_jac(acc);
      }
    }
    let point = g2_load_from(0u, i * num_windows + u32(win));
    if (g2_jac_is_infinity(point)) {
      continue;
    }
    acc = g2_add_jac(acc, point);
  }
  g2_store(i, g2_jac_to_affine(acc));
}
