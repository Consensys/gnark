import { bytesToHex } from "./browser_utils.js";

export type ScalarBatch = {
  hexes: string[];
  words: Uint32Array;
};

export type SparseSignedBucketMetadata = {
  baseIndices: Uint32Array;
  bucketPointers: Uint32Array;
  bucketSizes: Uint32Array;
  bucketValues: Uint32Array;
  windowStarts: Uint32Array;
  windowCounts: Uint32Array;
  numWindows: number;
  bucketCount: number;
};

export const INDEX_SIGN_BIT = 0x80000000;

export function bestPippengerWindow(count: number): number {
  const windows = [4, 5, 6, 7, 8, 9, 10, 11, 12];
  let best = windows[0];
  let bestCost = Number.POSITIVE_INFINITY;
  for (const window of windows) {
    const cost = Math.ceil(255 / window) * (count + (1 << window));
    if (cost < bestCost) {
      bestCost = cost;
      best = window;
    }
  }
  return best;
}

export function hexesToScalarWords(hexes: readonly string[]): Uint32Array {
  const words = new Uint32Array(hexes.length * 8);
  for (let i = 0; i < hexes.length; i += 1) {
    const hex = hexes[i];
    for (let byteIndex = 0; byteIndex < 32; byteIndex += 1) {
      const value = Number.parseInt(hex.slice(byteIndex * 2, byteIndex * 2 + 2), 16);
      words[i * 8 + (byteIndex >>> 2)] |= value << ((byteIndex & 3) * 8);
    }
  }
  return words;
}

export function makeRandomScalarBatch(count: number, salt = 0x9e3779b9): ScalarBatch {
  const hexes = new Array<string>(count);
  const words = new Uint32Array(count * 8);
  for (let index = 0; index < count; index += 1) {
    const scalar = makeRandomScalarData((salt ^ count ^ index) >>> 0);
    hexes[index] = scalar.hex;
    words.set(scalar.words, index * 8);
  }
  return { hexes, words };
}

export function buildSparseSignedBucketMetadataWords(
  scalarWords: Uint32Array,
  count: number,
  termsPerInstance: number,
  window: number,
  maxChunkSize = 256,
): SparseSignedBucketMetadata {
  const numWindows = Math.ceil(256 / window) + 1;
  const bucketCount = 1 << (window - 1);
  const totalWindows = count * numWindows;
  const logicalBucketSizes = new Uint32Array(totalWindows * bucketCount);
  const half = 1 << (window - 1);
  const full = 1 << window;

  for (let instance = 0; instance < count; instance += 1) {
    const baseOffset = instance * termsPerInstance;
    for (let term = 0; term < termsPerInstance; term += 1) {
      const idx = baseOffset + term;
      const scalarBase = idx * 8;
      let carry = 0;
      for (let win = 0; win < numWindows; win += 1) {
        const unsigned = win < numWindows - 1 ? extractWindowDigitWords(scalarWords, scalarBase, win * window, window) : 0;
        let value = unsigned + carry;
        carry = 0;
        if (value >= half) {
          value = full - value;
          if (value !== 0) {
            const slot = (instance * numWindows + win) * bucketCount + (value - 1);
            logicalBucketSizes[slot] += 1;
          }
          carry = 1;
        } else if (value !== 0) {
          const slot = (instance * numWindows + win) * bucketCount + (value - 1);
          logicalBucketSizes[slot] += 1;
        }
      }
    }
  }

  const logicalBucketPointers = new Uint32Array(totalWindows * bucketCount);
  let totalEntries = 0;
  for (let i = 0; i < logicalBucketSizes.length; i += 1) {
    logicalBucketPointers[i] = totalEntries;
    totalEntries += logicalBucketSizes[i];
  }
  const baseIndices = new Uint32Array(totalEntries);
  const writeOffsets = logicalBucketPointers.slice();

  for (let instance = 0; instance < count; instance += 1) {
    const baseOffset = instance * termsPerInstance;
    for (let term = 0; term < termsPerInstance; term += 1) {
      const idx = baseOffset + term;
      const scalarBase = idx * 8;
      let carry = 0;
      for (let win = 0; win < numWindows; win += 1) {
        const unsigned = win < numWindows - 1 ? extractWindowDigitWords(scalarWords, scalarBase, win * window, window) : 0;
        let value = unsigned + carry;
        carry = 0;
        let neg = false;
        if (value >= half) {
          value = full - value;
          neg = value !== 0;
          carry = 1;
        }
        if (value === 0) {
          continue;
        }
        const slot = (instance * numWindows + win) * bucketCount + (value - 1);
        const raw = neg ? ((idx | INDEX_SIGN_BIT) >>> 0) : idx;
        baseIndices[writeOffsets[slot]] = raw;
        writeOffsets[slot] += 1;
      }
    }
  }

  const bucketPointers: number[] = [];
  const bucketSizes: number[] = [];
  const bucketValues: number[] = [];
  const windowStarts = new Uint32Array(totalWindows);
  const windowCounts = new Uint32Array(totalWindows);
  for (let windowSlot = 0; windowSlot < totalWindows; windowSlot += 1) {
    windowStarts[windowSlot] = bucketPointers.length;
    let dispatchedInWindow = 0;
    const bucketBase = windowSlot * bucketCount;
    for (let value = 1; value <= bucketCount; value += 1) {
      const slot = bucketBase + (value - 1);
      const size = logicalBucketSizes[slot];
      if (size === 0) {
        continue;
      }
      const ptr = logicalBucketPointers[slot];
      for (let offset = 0; offset < size; offset += maxChunkSize) {
        bucketPointers.push(ptr + offset);
        bucketSizes.push(Math.min(size - offset, maxChunkSize));
        bucketValues.push(value);
        dispatchedInWindow += 1;
      }
    }
    windowCounts[windowSlot] = dispatchedInWindow;
  }

  return {
    baseIndices,
    bucketPointers: Uint32Array.from(bucketPointers),
    bucketSizes: Uint32Array.from(bucketSizes),
    bucketValues: Uint32Array.from(bucketValues),
    windowStarts,
    windowCounts,
    numWindows,
    bucketCount,
  };
}

function extractWindowDigitWords(words: Uint32Array, scalarBase: number, bitOffset: number, window: number): number {
  if (window <= 0) {
    return 0;
  }
  const word = Math.floor(bitOffset / 32);
  const shift = bitOffset % 32;
  const mask = (1 << window) - 1;
  if (word >= 8) {
    return 0;
  }
  const lo = words[scalarBase + word] >>> shift;
  if (shift + window <= 32 || word + 1 >= 8) {
    return lo & mask;
  }
  const highWidth = shift + window - 32;
  const hiMask = (1 << highWidth) - 1;
  const hi = words[scalarBase + word + 1] & hiMask;
  return (lo | (hi << (32 - shift))) & mask;
}

function makeRandomScalarData(seed: number): { hex: string; words: Uint32Array } {
  const bytes = new Uint8Array(32);
  const words = new Uint32Array(8);
  let state = seed >>> 0;
  for (let i = 0; i < bytes.length; i += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    const value = state & 0xff;
    bytes[i] = value;
    words[i >>> 2] |= value << ((i & 3) * 8);
  }
  return { hex: bytesToHex(bytes), words };
}
