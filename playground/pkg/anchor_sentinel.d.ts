/* tslint:disable */
/* eslint-disable */

/**
 * Install a `console.error` panic hook so a panic inside the WASM
 * module shows up in the browser's devtools rather than as a silent
 * abort. Idempotent; safe to call multiple times.
 */
export function _start(): void;

/**
 * Scan a single IDL + Rust source pair and return findings as a
 * JavaScript value.
 *
 * `idl_json` is the raw text of an Anchor IDL file (0.30+ or legacy
 * 0.29; the parser auto-detects). `rust_src` is the raw text of an
 * Anchor `programs/<name>/src/lib.rs`. Either can be empty, in which
 * case the corresponding analysis layer is skipped.
 *
 * The return value is a plain JS array of finding objects, each
 * shaped like:
 *
 * ```ts
 * {
 *   rule: string,
 *   severity: "critical" | "high" | "medium" | "low" | "info",
 *   program: string,
 *   instruction: string | null,
 *   account: string | null,
 *   file: string | null,
 *   line: number | null,
 *   column: number | null,
 *   message: string,
 *   hint: string | null,
 * }
 * ```
 *
 * Parse errors are returned as a single error object: `[{ error: "..." }]`.
 */
export function scan(idl_json: string, rust_src: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly scan: (a: number, b: number, c: number, d: number) => number;
    readonly _start: () => void;
    readonly __wbindgen_export: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
