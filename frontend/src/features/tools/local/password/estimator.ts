/**
 * Lazy-loaded zxcvbn engine. The dictionaries are several hundred KB, so they
 * live in their own chunk, bundled with the app and loaded from our own
 * origin: no CDN, no network call with the password.
 */

import type { ZxcvbnFactory, ZxcvbnResult } from "@zxcvbn-ts/core";

import { MAX_PASSWORD_CHARS } from "./analysis";

let engine: Promise<ZxcvbnFactory> | null = null;

export function loadEstimator(): Promise<ZxcvbnFactory> {
  engine ??= Promise.all([
    import("@zxcvbn-ts/core"),
    import("@zxcvbn-ts/language-common"),
    import("@zxcvbn-ts/language-en"),
  ])
    .then(
      ([core, common, en]) =>
        new core.ZxcvbnFactory({
          dictionary: { ...common.dictionary, ...en.dictionary },
          graphs: common.adjacencyGraphs,
          translations: en.translations,
          // Matching is super-linear in length; cap the work.
          maxLength: MAX_PASSWORD_CHARS,
        }),
    )
    .catch((error: unknown) => {
      engine = null; // allow a retry
      throw error;
    });
  return engine;
}

export async function estimate(password: string): Promise<ZxcvbnResult> {
  return (await loadEstimator()).check(password.slice(0, MAX_PASSWORD_CHARS));
}
