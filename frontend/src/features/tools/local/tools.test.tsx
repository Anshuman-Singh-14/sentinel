/** Behaviour of the local tool UIs (the algorithms are tested beside each module). */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { base64UrlEncode, utf8Encode } from "./shared/bytes";
import EncoderTool from "./encoder/EncoderTool";
import HashTool from "./hash/HashTool";
import JwtTool from "./jwt/JwtTool";
import PasswordTool from "./password/PasswordTool";

const segment = (v: unknown) => base64UrlEncode(utf8Encode(JSON.stringify(v)));

describe("every local tool", () => {
  it.each([
    ["Encoder", EncoderTool],
    ["Hash", HashTool],
    ["JWT", JwtTool],
    ["Password", PasswordTool],
  ])("%s shows the local-only badge and explainers", (_name, Tool) => {
    render(<Tool />);
    expect(screen.getByText("Runs locally — nothing leaves your browser")).toBeInTheDocument();
    expect(screen.getAllByRole("group").length).toBeGreaterThan(0); // <details> explainers
  });
});

describe("EncoderTool", () => {
  it("warns that encoding is not encryption", () => {
    render(<EncoderTool />);
    expect(screen.getByText(/encoding is not encryption/i)).toBeInTheDocument();
    expect(
      screen.getByRole("table", { name: /encoding versus hashing versus encryption/i }),
    ).toBeInTheDocument();
  });

  it("decodes, reports errors and suggests other formats", async () => {
    render(<EncoderTool />);
    await userEvent.click(screen.getByLabelText("decode"));
    const input = screen.getByLabelText("Base64 to decode");
    await userEvent.type(input, "aGVsbG8=");
    expect(
      within(screen.getByRole("region", { name: "Output" })).getByText("hello"),
    ).toBeInTheDocument();
    expect(screen.getByText(/round-trip check passed/i)).toBeInTheDocument();

    await userEvent.clear(input);
    await userEvent.type(input, "ab$");
    expect(screen.getByRole("alert")).toHaveTextContent(/"\$" at position 3/);

    await userEvent.clear(input);
    await userEvent.type(input, "68656c6c6f");
    await userEvent.click(screen.getByRole("button", { name: "Hex" }));
    expect(
      within(screen.getByRole("region", { name: "Output" })).getByText("hello"),
    ).toBeInTheDocument();
  });

  it("shows binary output as hex", async () => {
    render(<EncoderTool />);
    await userEvent.click(screen.getByLabelText("Hex"));
    await userEvent.click(screen.getByLabelText("decode"));
    await userEvent.type(screen.getByLabelText("Hex to decode"), "fffe");
    expect(screen.getByText(/2 bytes of binary data/)).toBeInTheDocument();
  });

  it("swaps output back into the input", async () => {
    render(<EncoderTool />);
    await userEvent.type(screen.getByLabelText("Text to encode"), "hi");
    await userEvent.click(screen.getByRole("button", { name: /use output as input/i }));
    expect(screen.getByLabelText("Base64 to decode")).toHaveValue("aGk=");
  });
});

describe("HashTool", () => {
  it("marks legacy algorithms and verifies a pasted checksum", async () => {
    render(<HashTool />);
    await userEvent.click(screen.getByLabelText(/^MD5/));
    await userEvent.type(screen.getByLabelText("Text to hash"), "abc");
    expect(await screen.findByText("900150983cd24fb0d6963f7d28e17f72")).toBeInTheDocument();
    expect(screen.getAllByText(/Legacy — not collision resistant/).length).toBeGreaterThan(0);

    await userEvent.type(
      screen.getByLabelText(/expected hash/i),
      "900150983CD24FB0D6963F7D28E17F72",
    );
    expect(await screen.findByText(/Match: identical MD5 digest/)).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText(/expected hash/i));
    await userEvent.type(screen.getByLabelText(/expected hash/i), "0".repeat(32));
    expect(await screen.findByText(/No match/)).toBeInTheDocument();
  });

  it("explains why passwords need slow hashes", () => {
    render(<HashTool />);
    expect(screen.getByText(/why passwords need slow hashes/i)).toBeInTheDocument();
  });
});

describe("JwtTool", () => {
  it("says decoding is not verifying and flags alg none", async () => {
    render(<JwtTool />);
    expect(screen.getByText(/decoding is not verifying/i)).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("JWT"));
    await userEvent.paste(`${segment({ alg: "none" })}.${segment({ sub: "admin" })}.`);
    expect(await screen.findByText('Unsigned token: alg is "none"')).toBeInTheDocument();
    expect(screen.getByText(/cannot be verified: it is unsigned/i)).toBeInTheDocument();
    expect(screen.getByRole("tree", { name: "JWT payload" })).toHaveTextContent('"sub": "admin"');
  });

  it("shows a clear error for a malformed token", async () => {
    render(<JwtTool />);
    await userEvent.type(screen.getByLabelText("JWT"), "not-a-jwt");
    expect(screen.getByRole("alert")).toHaveTextContent(/three dot-separated parts/);
  });

  it("renders the claim timeline", async () => {
    const now = Math.floor(Date.now() / 1000);
    render(<JwtTool />);
    await userEvent.click(screen.getByLabelText("JWT"));
    await userEvent.paste(
      `${segment({ alg: "HS256" })}.${segment({ iat: now, exp: now + 7200 })}.sig`,
    );
    expect(await screen.findByText(/in 2 hours/)).toBeInTheDocument();
  });

  it("warns about a short HMAC secret", async () => {
    render(<JwtTool />);
    await userEvent.click(screen.getByLabelText("JWT"));
    await userEvent.paste(`${segment({ alg: "HS256" })}.${segment({ exp: 1 })}.sig`);
    await userEvent.type(await screen.findByLabelText("Shared secret"), "short");
    expect(screen.getByText(/requires at least 32/)).toBeInTheDocument();
  });
});

describe("PasswordTool", () => {
  it("masks by default and toggles visibility", async () => {
    render(<PasswordTool />);
    const input = screen.getByLabelText("Password to analyse");
    expect(input).toHaveAttribute("type", "password");
    expect(input).toHaveAttribute("autocomplete", "off");
    await userEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(input).toHaveAttribute("type", "text");
  });

  it("contrasts the two entropy estimates and shows crack-time assumptions", async () => {
    render(<PasswordTool />);
    await userEvent.type(screen.getByLabelText("Password to analyse"), "P@ssw0rd1990");
    expect(
      await screen.findByText(/overstates strength/, {}, { timeout: 10_000 }),
    ).toBeInTheDocument();
    expect(screen.getByText("Charset entropy", { selector: "p" })).toBeInTheDocument();
    expect(screen.getByText("Pattern-aware estimate", { selector: "p" })).toBeInTheDocument();
    const table = screen.getByRole("table", { name: /crack-time estimates/i });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).getByText(/Offline, fast hash/)).toBeInTheDocument();
    expect(screen.getByText(/password manager/i, { selector: "li" })).toBeInTheDocument();
    // Pattern tokens are masked while the password is hidden.
    expect(screen.queryByText("P@ssw0rd")).not.toBeInTheDocument();
  });
});
