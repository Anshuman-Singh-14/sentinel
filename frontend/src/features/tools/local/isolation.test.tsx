/**
 * Runtime privacy and offline guarantee for the client-side tools
 * (CLAUDE.md rule 2; Phase 4 acceptance).
 *
 * Every network, beacon and storage API is replaced by a spy that records the
 * call and then fails, as if the machine were offline. Each tool is then
 * driven through its main flow. The tools must produce their results and the
 * spies must stay untouched.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { base64UrlEncode, utf8Encode } from "./shared/bytes";
import EncoderTool from "./encoder/EncoderTool";
import HashTool from "./hash/HashTool";
import JwtTool from "./jwt/JwtTool";
import PasswordTool from "./password/PasswordTool";

const calls: string[] = [];

function trap(name: string) {
  return vi.fn(() => {
    calls.push(name);
    throw new TypeError(`${name} is unavailable (offline)`);
  });
}

beforeEach(() => {
  calls.length = 0;
  vi.stubGlobal("fetch", trap("fetch"));
  vi.stubGlobal("XMLHttpRequest", trap("XMLHttpRequest"));
  vi.stubGlobal("WebSocket", trap("WebSocket"));
  vi.stubGlobal("EventSource", trap("EventSource"));
  Object.defineProperty(navigator, "sendBeacon", { value: trap("sendBeacon"), configurable: true });
  Object.defineProperty(navigator, "onLine", { value: false, configurable: true });
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
    calls.push("storage.setItem");
  });
});

afterEach(() => {
  expect(calls).toEqual([]);
  Object.defineProperty(navigator, "onLine", { value: true, configurable: true });
});

const segment = (v: unknown) => base64UrlEncode(utf8Encode(JSON.stringify(v)));

describe("local tools work offline and never touch the network or storage", () => {
  it("encoder", async () => {
    render(<EncoderTool />);
    await userEvent.type(screen.getByLabelText("Text to encode"), "secret value");
    expect(await screen.findByText("c2VjcmV0IHZhbHVl")).toBeInTheDocument();
  });

  it("hash (text and file)", async () => {
    render(<HashTool />);
    await userEvent.type(screen.getByLabelText("Text to hash"), "abc");
    expect(
      await screen.findByText("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: "File" }));
    const file = new File(["abc"], "abc.txt");
    await userEvent.upload(screen.getByLabelText(/choose a file/i), file);
    expect(await screen.findByText("abc.txt")).toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.getByText("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
      ).toBeInTheDocument(),
    );
  });

  it("JWT inspector, including local signature verification", async () => {
    const secret = "an-hmac-secret-that-is-at-least-32-bytes";
    const input = `${segment({ alg: "HS256", typ: "JWT" })}.${segment({ sub: "alice" })}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)),
    );
    const token = `${input}.${base64UrlEncode(sig)}`;

    render(<JwtTool />);
    await userEvent.click(screen.getByLabelText("JWT"));
    await userEvent.paste(token);
    expect(await screen.findByText("No expiry (exp)")).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Shared secret"));
    await userEvent.paste(secret);
    await userEvent.click(screen.getByRole("button", { name: /verify signature locally/i }));
    expect(await screen.findByText(/signature valid/i)).toBeInTheDocument();
  });

  it("password analyzer (dictionaries are bundled, not fetched)", async () => {
    render(<PasswordTool />);
    await userEvent.type(screen.getByLabelText("Password to analyse"), "P@ssw0rd1990");
    expect(await screen.findByText("Leetspeak word", {}, { timeout: 10_000 })).toBeInTheDocument();
  });
});
