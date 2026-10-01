import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";

describe("App health placeholder", () => {
  it("shows healthy status and version when /health responds", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "ok", version: "0.1.0" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByText(/API healthy/i)).toBeInTheDocument();
    expect(screen.getByText("(v0.1.0)")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/health", expect.objectContaining({ method: "GET" }));
  });

  it("shows unreachable when the request fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network down")));

    render(<App />);

    expect(await screen.findByText(/API unreachable/i)).toBeInTheDocument();
  });

  it("shows unreachable on a non-2xx response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 502 })));

    render(<App />);

    expect(await screen.findByText(/API unreachable/i)).toBeInTheDocument();
  });
});
