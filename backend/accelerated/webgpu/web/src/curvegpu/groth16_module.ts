import type {
  CurveGPUContext,
  G1Module,
  G1MSMModule,
  G2Module,
  G2MSMModule,
  Groth16ConstraintSystem,
  Groth16Handle,
  Groth16Module,
  Groth16ProvingKey,
  Groth16ProvingKeyFormat,
  Groth16QuotientModule,
  Groth16RuntimeKind,
  Groth16RuntimeOptions,
  Groth16VerificationKey,
  SupportedCurveID,
} from "./api.js";
import { installGroth16WebGPUBridge } from "./groth16_webgpu_bridge.js";

type GoInstance = {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
};

type GoConstructor = new () => GoInstance;

type RuntimeGlobal = {
  readConstraintSystem(curve: SupportedCurveID, bytes: Uint8Array): Promise<{ handle: string; constraints: number }>;
  readProvingKey(curve: SupportedCurveID, bytes: Uint8Array, format: Groth16ProvingKeyFormat): Promise<{ handle: string }>;
  readVerificationKey(curve: SupportedCurveID, bytes: Uint8Array): Promise<{ handle: string }>;
  prepareProvingKey(handle: string): Promise<void>;
  prove(ccsHandle: string, pkHandle: string, witness: Uint8Array): Promise<Uint8Array>;
  verify(proof: Uint8Array, vkHandle: string, publicWitness: Uint8Array): Promise<boolean>;
  release(handle: string): Promise<void>;
};

type Groth16ModuleConfig = {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  modulusHex: string;
  frBytes: number;
  quotient: Groth16QuotientModule;
  g1: G1Module;
  g2: G2Module;
  g1msm: G1MSMModule;
  g2msm: G2MSMModule;
};

export const defaultGroth16RuntimeURLs = Object.freeze({
  wasmExecURL: new URL("../../assets/wasm_exec.js", import.meta.url).toString(),
  webgpuWasmURL: new URL("../../assets/groth16-webgpu.wasm", import.meta.url).toString(),
  nativeWasmURL: new URL("../../assets/groth16-native.wasm", import.meta.url).toString(),
});

const runtimeGlobals: Record<Groth16RuntimeKind, string> = {
  webgpu: "gnarkGroth16RuntimeWebGPU",
  native: "gnarkGroth16RuntimeNative",
};

const loadedScripts = new Map<string, Promise<void>>();
const loadedRuntimes = new Map<string, Promise<RuntimeGlobal>>();

function cloneBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function getGlobalObject<T>(name: string): T | undefined {
  return (globalThis as typeof globalThis & Record<string, T | undefined>)[name];
}

function setGlobalObject<T>(name: string, value: T | undefined): void {
  (globalThis as typeof globalThis & Record<string, T | undefined>)[name] = value;
}

function getGoConstructor(): GoConstructor {
  const Go = getGlobalObject<GoConstructor>("Go");
  if (typeof Go !== "function") {
    throw new Error("Go WASM runtime is not available after loading wasm_exec.js");
  }
  return Go;
}

async function loadScript(url: string): Promise<void> {
  if (typeof document === "undefined") {
    throw new Error("Groth16 WASM runtime loading requires a browser document");
  }
  let promise = loadedScripts.get(url);
  if (!promise) {
    promise = new Promise<void>((resolve, reject) => {
      const script = document.createElement("script");
      script.src = url;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`failed to load ${url}`));
      document.head.appendChild(script);
    });
    loadedScripts.set(url, promise);
  }
  await promise;
}

async function ensureWasmExec(url: string): Promise<void> {
  if (typeof getGlobalObject<GoConstructor>("Go") === "function") {
    return;
  }
  await loadScript(url);
}

async function waitForRuntimeGlobal(name: string): Promise<RuntimeGlobal> {
  const deadline = performance.now() + 10_000;
  while (performance.now() < deadline) {
    const runtime = getGlobalObject<RuntimeGlobal>(name);
    if (runtime) {
      return runtime;
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`Groth16 WASM runtime ${name} did not initialize`);
}

async function loadGoRuntime(
  kind: Groth16RuntimeKind,
  options: Required<Groth16RuntimeOptions>,
  beforeStart: () => void,
): Promise<RuntimeGlobal> {
  const wasmURL = kind === "native" ? options.nativeWasmURL : options.webgpuWasmURL;
  const cacheKey = `${kind}\n${options.wasmExecURL}\n${wasmURL}`;
  let promise = loadedRuntimes.get(cacheKey);
  if (!promise) {
    promise = (async () => {
      beforeStart();
      await ensureWasmExec(options.wasmExecURL);
      const response = await fetch(wasmURL);
      if (!response.ok) {
        throw new Error(`failed to fetch ${wasmURL}: ${response.status}`);
      }
      const bytes = await response.arrayBuffer();
      const go = new (getGoConstructor())();
      const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
      setGlobalObject<RuntimeGlobal>(runtimeGlobals[kind], undefined);
      void go.run(instance).catch((error: unknown) => {
        console.error(`Groth16 ${kind} WASM runtime exited`, error);
      });
      return waitForRuntimeGlobal(runtimeGlobals[kind]);
    })();
    loadedRuntimes.set(cacheKey, promise);
  } else {
    beforeStart();
  }
  return promise;
}

function normalizeRuntimeOptions(options?: Groth16RuntimeOptions): Required<Groth16RuntimeOptions> {
  return {
    wasmExecURL: options?.wasmExecURL ?? defaultGroth16RuntimeURLs.wasmExecURL,
    webgpuWasmURL: options?.webgpuWasmURL ?? defaultGroth16RuntimeURLs.webgpuWasmURL,
    nativeWasmURL: options?.nativeWasmURL ?? defaultGroth16RuntimeURLs.nativeWasmURL,
  };
}

class RuntimeHandle implements Groth16Handle {
  #disposed = false;

  constructor(
    readonly runtime: RuntimeGlobal,
    readonly kind: Groth16RuntimeKind,
    readonly curve: SupportedCurveID,
    readonly type: "ccs" | "pk" | "vk",
    readonly handle: string,
  ) {}

  async dispose(): Promise<void> {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    await this.runtime.release(this.handle);
  }

  assertUsable(expectedType: RuntimeHandle["type"]): void {
    if (this.#disposed) {
      throw new Error(`Groth16 ${this.type} handle has been disposed`);
    }
    if (this.type !== expectedType) {
      throw new Error(`expected Groth16 ${expectedType} handle, got ${this.type}`);
    }
  }
}

class ConstraintSystemHandle extends RuntimeHandle implements Groth16ConstraintSystem {
  constructor(runtime: RuntimeGlobal, kind: Groth16RuntimeKind, curve: SupportedCurveID, handle: string, readonly constraints: number) {
    super(runtime, kind, curve, "ccs", handle);
  }
}

class ProvingKeyHandle extends RuntimeHandle implements Groth16ProvingKey {
  constructor(runtime: RuntimeGlobal, kind: Groth16RuntimeKind, curve: SupportedCurveID, handle: string) {
    super(runtime, kind, curve, "pk", handle);
  }
}

class VerificationKeyHandle extends RuntimeHandle implements Groth16VerificationKey {
  constructor(runtime: RuntimeGlobal, kind: Groth16RuntimeKind, curve: SupportedCurveID, handle: string) {
    super(runtime, kind, curve, "vk", handle);
  }
}

function runtimeHandle(handle: Groth16Handle, type: RuntimeHandle["type"]): RuntimeHandle {
  if (!(handle instanceof RuntimeHandle)) {
    throw new Error("Groth16 handle was not created by this module");
  }
  handle.assertUsable(type);
  return handle;
}

function assertSameRuntime(a: RuntimeHandle, b: RuntimeHandle): void {
  if (a.runtime !== b.runtime || a.kind !== b.kind) {
    throw new Error("Groth16 handles belong to different runtimes");
  }
  if (a.curve !== b.curve) {
    throw new Error(`Groth16 handles belong to different curves: ${a.curve} and ${b.curve}`);
  }
}

function writeUint32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

function writeBigIntBE(out: Uint8Array, offset: number, byteSize: number, value: bigint): void {
  let remaining = value;
  for (let i = byteSize - 1; i >= 0; i--) {
    out[offset + i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

export function createGroth16Module(config: Groth16ModuleConfig): Groth16Module {
  const modulus = BigInt(config.modulusHex);
  let currentRuntime: Promise<RuntimeGlobal> | null = null;
  let currentKind: Groth16RuntimeKind = "webgpu";

  function installBridge(): void {
    installGroth16WebGPUBridge({
      context: config.context,
      curve: config.curve,
      g1: config.g1,
      g2: config.g2,
      g1msm: config.g1msm,
      g2msm: config.g2msm,
      quotient: config.quotient,
    });
  }

  async function loadRuntime(options?: Groth16RuntimeOptions & { kind?: Groth16RuntimeKind }): Promise<void> {
    currentKind = options?.kind ?? "webgpu";
    const runtimeOptions = normalizeRuntimeOptions(options);
    currentRuntime = loadGoRuntime(currentKind, runtimeOptions, currentKind === "webgpu" ? installBridge : () => {});
    await currentRuntime;
  }

  async function getRuntime(): Promise<{ runtime: RuntimeGlobal; kind: Groth16RuntimeKind }> {
    if (!currentRuntime) {
      await loadRuntime();
    }
    return { runtime: await currentRuntime!, kind: currentKind };
  }

  return {
    context: config.context,
    curve: config.curve,
    computeGroth16QuotientPackedRegular(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array> {
      return config.quotient.computeGroth16QuotientPackedRegular(a, b, c);
    },
    computeGroth16QuotientPackedMont(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array> {
      return config.quotient.computeGroth16QuotientPackedMont(a, b, c);
    },
    prewarmGroth16QuotientDomain(size: number): Promise<void> {
      return config.quotient.prewarmGroth16QuotientDomain(size);
    },
    loadRuntime,
    async readConstraintSystem(bytes: Uint8Array): Promise<Groth16ConstraintSystem> {
      const { runtime, kind } = await getRuntime();
      const result = await runtime.readConstraintSystem(config.curve, cloneBytes(bytes));
      return new ConstraintSystemHandle(runtime, kind, config.curve, result.handle, result.constraints);
    },
    async readProvingKey(bytes: Uint8Array, options?: { format?: Groth16ProvingKeyFormat }): Promise<Groth16ProvingKey> {
      const { runtime, kind } = await getRuntime();
      const result = await runtime.readProvingKey(config.curve, cloneBytes(bytes), options?.format ?? "serialized");
      return new ProvingKeyHandle(runtime, kind, config.curve, result.handle);
    },
    async readVerificationKey(bytes: Uint8Array): Promise<Groth16VerificationKey> {
      const { runtime, kind } = await getRuntime();
      const result = await runtime.readVerificationKey(config.curve, cloneBytes(bytes));
      return new VerificationKeyHandle(runtime, kind, config.curve, result.handle);
    },
    async prepareProvingKey(pk: Groth16ProvingKey): Promise<void> {
      const pkHandle = runtimeHandle(pk, "pk");
      await pkHandle.runtime.prepareProvingKey(pkHandle.handle);
    },
    async prove(ccs: Groth16ConstraintSystem, pk: Groth16ProvingKey, witness: Uint8Array): Promise<Uint8Array> {
      const ccsHandle = runtimeHandle(ccs, "ccs");
      const pkHandle = runtimeHandle(pk, "pk");
      assertSameRuntime(ccsHandle, pkHandle);
      return ccsHandle.runtime.prove(ccsHandle.handle, pkHandle.handle, cloneBytes(witness));
    },
    async verify(proof: Uint8Array, vk: Groth16VerificationKey, publicWitness: Uint8Array): Promise<boolean> {
      const vkHandle = runtimeHandle(vk, "vk");
      return vkHandle.runtime.verify(cloneBytes(proof), vkHandle.handle, cloneBytes(publicWitness));
    },
    encodeWitness(values: readonly bigint[], options: { publicCount: number }): Uint8Array {
      if (!Number.isInteger(options.publicCount) || options.publicCount < 0 || options.publicCount > values.length) {
        throw new Error(`invalid publicCount ${options.publicCount}`);
      }
      const out = new Uint8Array(12 + values.length * config.frBytes);
      writeUint32BE(out, 0, options.publicCount);
      writeUint32BE(out, 4, values.length - options.publicCount);
      writeUint32BE(out, 8, values.length);
      for (let i = 0; i < values.length; i++) {
        const value = values[i];
        if (value < 0n || value >= modulus) {
          throw new Error(`witness value at index ${i} is outside the scalar field`);
        }
        writeBigIntBE(out, 12 + i * config.frBytes, config.frBytes, value);
      }
      return out;
    },
  };
}
