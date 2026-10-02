import { describe, expect, it } from "vitest";

import { bytesToHex } from "../shared/bytes";
import {
  ALGORITHM_ORDER,
  MAX_FILE_BYTES,
  FileTooLargeError,
  algorithmsForLength,
  compareDigest,
  formatBytes,
  hashBytesSync,
  hashFile,
  hashText,
  normalizeDigest,
} from "./hashing";

// FIPS 180 / RFC 1321 known-answer vectors for "abc".
const ABC = {
  "SHA-256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  "SHA-384":
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
  "SHA-512":
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  "SHA-1": "a9993e364706816aba3e25717850c26c9cd0d89d",
  MD5: "900150983cd24fb0d6963f7d28e17f72",
} as const;

const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

describe("hashText", () => {
  it.each(ALGORITHM_ORDER)("%s matches the standard test vector for 'abc'", async (algorithm) => {
    expect(await hashText(algorithm, "abc")).toBe(ABC[algorithm]);
  });

  it("hashes the empty string", async () => {
    expect(await hashText("SHA-256", "")).toBe(EMPTY_SHA256);
  });

  it("hashes text as UTF-8", async () => {
    // SHA-256("é") over the UTF-8 bytes C3 A9.
    expect(await hashText("SHA-256", "é")).toBe(
      bytesToHex(hashBytesSync("SHA-256", Uint8Array.from([0xc3, 0xa9]))),
    );
  });

  it("noble and Web Crypto agree on random input", async () => {
    const bytes = crypto.getRandomValues(new Uint8Array(10_000));
    for (const algorithm of ["SHA-256", "SHA-384", "SHA-512", "SHA-1"] as const) {
      const web = new Uint8Array(await crypto.subtle.digest(algorithm, bytes));
      expect(bytesToHex(hashBytesSync(algorithm, bytes))).toBe(bytesToHex(web));
    }
  });
});

describe("hashFile (streaming)", () => {
  it("computes several digests in one pass and reports progress", async () => {
    const file = new Blob(["a", "b", "c"]);
    const progress: number[] = [];
    const result = await hashFile(file, ["SHA-256", "MD5"], {
      onProgress: (p) => progress.push(p),
    });
    expect(result).toEqual({ "SHA-256": ABC["SHA-256"], MD5: ABC.MD5 });
    expect(progress[0]).toBe(0);
    expect(progress.at(-1)).toBe(1);
  });

  it("matches a one-shot hash for a multi-chunk file", async () => {
    const bytes = crypto.getRandomValues(new Uint8Array(65_536));
    const big = new Blob(Array.from({ length: 160 }, () => bytes)); // 10 MiB, several chunks
    const expected = bytesToHex(hashBytesSync("SHA-256", new Uint8Array(await big.arrayBuffer())));
    expect((await hashFile(big, ["SHA-256"]))["SHA-256"]).toBe(expected);
  });

  it("hashes an empty file", async () => {
    expect((await hashFile(new Blob([]), ["SHA-256"]))["SHA-256"]).toBe(EMPTY_SHA256);
  });

  it("can be cancelled", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      hashFile(new Blob(["data"]), ["SHA-256"], { signal: controller.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });

  it("refuses files over the size limit before reading them", async () => {
    const fake = { size: MAX_FILE_BYTES + 1 } as Blob;
    await expect(hashFile(fake, ["SHA-256"])).rejects.toBeInstanceOf(FileTooLargeError);
  });
});

describe("digest normalisation and comparison", () => {
  it.each([
    ["  BA7816BF 8F01CFEA  ", "ba7816bf8f01cfea"],
    ["sha256:ABCDEF", "abcdef"],
    ["0xABCDEF", "abcdef"],
    [`${ABC["SHA-256"]}  ubuntu.iso`, ABC["SHA-256"]],
  ])("normalises %j", (input, expected) => {
    expect(normalizeDigest(input)).toBe(expected);
  });

  it("rejects non-hex input", () => {
    expect(normalizeDigest("not a hash")).toBeNull();
    expect(normalizeDigest("")).toBeNull();
  });

  it("finds the matching algorithm", () => {
    expect(
      compareDigest(ABC.MD5.toUpperCase(), { "SHA-256": ABC["SHA-256"], MD5: ABC.MD5 }),
    ).toEqual({
      kind: "match",
      algorithm: "MD5",
    });
  });

  it("reports a mismatch with the algorithms the expected length suggests", () => {
    expect(compareDigest("0".repeat(64), { "SHA-256": ABC["SHA-256"] })).toEqual({
      kind: "mismatch",
      expectedAlgorithms: ["SHA-256"],
    });
    expect(compareDigest("zz", {})).toEqual({ kind: "invalid" });
  });

  it("maps digest lengths to algorithms", () => {
    expect(algorithmsForLength(40)).toEqual(["SHA-1"]);
    expect(algorithmsForLength(128)).toEqual(["SHA-512"]);
    expect(algorithmsForLength(10)).toEqual([]);
  });

  it("formats sizes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(4 * 1024 ** 3)).toBe("4.0 GiB");
  });
});
