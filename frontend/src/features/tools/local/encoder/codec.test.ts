import { describe, expect, it } from "vitest";

import {
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  bytesToHex,
  constantTimeEqual,
  hexToBytes,
  utf8Decode,
  utf8Encode,
} from "../shared/bytes";
import { decode, detectFormats, encode, roundTrips } from "./codec";

// RFC 4648 §10 test vectors.
const RFC4648: Array<[string, string]> = [
  ["", ""],
  ["f", "Zg=="],
  ["fo", "Zm8="],
  ["foo", "Zm9v"],
  ["foob", "Zm9vYg=="],
  ["fooba", "Zm9vYmE="],
  ["foobar", "Zm9vYmFy"],
];

describe("base64 (RFC 4648 vectors)", () => {
  it.each(RFC4648)("encodes %j as %j", (plain, encoded) => {
    expect(base64Encode(utf8Encode(plain))).toBe(encoded);
    expect(utf8Decode(base64Decode(encoded))).toBe(plain);
  });

  it("matches the platform encoder for all byte values", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    const binary = String.fromCharCode(...bytes);
    expect(base64Encode(bytes)).toBe(btoa(binary));
    expect(base64Decode(btoa(binary))).toEqual(bytes);
  });

  it("handles non-ASCII text that btoa cannot", () => {
    expect(encode("base64", "héllo ✓")).toBe("aMOpbGxvIOKckw==");
    expect(decode("base64", "aMOpbGxvIOKckw==").text).toBe("héllo ✓");
  });

  it.each([
    ["abc$", /"\$" at position 4/],
    ["Zm9v=Zg==", /padding/],
    ["Zg===", /padding/],
    ["Zm9vY", /impossible/],
    ["ab-_", /looks like Base64URL/],
  ])("rejects %j with a clear message", (input, message) => {
    expect(() => base64Decode(input)).toThrow(message);
  });

  it("ignores whitespace and line breaks (PEM style)", () => {
    expect(utf8Decode(base64Decode("Zm9v\nYmFy\r\n"))).toBe("foobar");
  });
});

describe("base64url", () => {
  it("uses - and _ and no padding", () => {
    const bytes = Uint8Array.from([0xfb, 0xff, 0xbf]);
    expect(base64Encode(bytes)).toBe("+/+/");
    expect(base64UrlEncode(bytes)).toBe("-_-_");
    expect(base64UrlEncode(utf8Encode("f"))).toBe("Zg");
    expect(base64UrlDecode("-_-_")).toEqual(bytes);
  });

  it("points out standard Base64 input", () => {
    expect(() => base64UrlDecode("+/+/")).toThrow(/looks like standard Base64/);
  });
});

describe("hex", () => {
  it("round-trips bytes", () => {
    expect(bytesToHex(Uint8Array.from([0, 15, 255]))).toBe("000fff");
    expect(hexToBytes("00 0F ff")).toEqual(Uint8Array.from([0, 15, 255]));
  });

  it.each([
    ["abc", /even number/],
    ["zz", /"z" at position 1/],
  ])("rejects %j", (input, message) => {
    expect(() => hexToBytes(input)).toThrow(message);
  });
});

describe("url encoding", () => {
  it("percent-encodes reserved and non-ASCII characters", () => {
    expect(encode("url", "a b&c=d/é")).toBe("a%20b%26c%3Dd%2F%C3%A9");
    expect(decode("url", "a%20b+c").text).toBe("a b c");
  });

  it("explains a broken escape", () => {
    expect(() => decode("url", "100%")).toThrow(/position 4/);
    expect(() => decode("url", "%E0%A4%A")).toThrow(/URL/);
  });
});

describe("decoding binary data", () => {
  it("returns null text for bytes that are not UTF-8", () => {
    const result = decode("hex", "fffe00");
    expect(result.text).toBeNull();
    expect(result.bytes).toEqual(Uint8Array.from([0xff, 0xfe, 0]));
  });
});

describe("round-trip check", () => {
  it.each(["base64", "base64url", "url", "hex"] as const)("encode → decode for %s", (format) => {
    expect(roundTrips(format, "encode", "Sentinel ✓ <tag> & 100%")).toBe(true);
  });

  it("accepts canonical input and flags non-canonical Base64", () => {
    expect(roundTrips("base64", "decode", "Zm9v")).toBe(true);
    expect(roundTrips("base64", "decode", "Zm8")).toBe(true); // missing padding is tolerated
    expect(roundTrips("base64", "decode", "Zm9=")).toBe(false); // non-zero trailing bits
    expect(roundTrips("hex", "decode", "ABCD")).toBe(true);
  });

  it("is false for undecodable input", () => {
    expect(roundTrips("hex", "decode", "xyz")).toBe(false);
  });
});

describe("format detection", () => {
  it.each([
    ["aGVsbG8gd29ybGQ=", "base64"],
    ["eyJhbGciOiJIUzI1NiJ9", "base64"],
    ["eyJzdWIiOiI_In0", "base64url"],
    ["68656c6c6f", "hex"],
    ["hello%20world", "url"],
  ])("suggests %j as %s", (input, format) => {
    expect(detectFormats(input).map((s) => s.format)).toContain(format);
  });

  it("does not suggest decodings that produce garbage", () => {
    expect(detectFormats("plain english words")).toEqual([]);
    expect(detectFormats("abcd")).toEqual([]); // valid Base64, but decodes to binary
  });
});

describe("constantTimeEqual", () => {
  it("compares strings", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "ab")).toBe(false);
    expect(constantTimeEqual("", "")).toBe(true);
  });
});
