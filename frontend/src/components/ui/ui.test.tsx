import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SEVERITIES } from "../../types/api";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { Card } from "./Card";
import { DataTable } from "./DataTable";
import type { Column } from "./DataTable";
import { Drawer } from "./Drawer";
import { JsonViewer } from "./JsonViewer";
import { SeverityBadge } from "./SeverityBadge";
import { Tabs } from "./Tabs";
import { TextField } from "./TextField";
import { ToastProvider, useToast } from "./Toast";

afterEach(() => {
  vi.useRealTimers();
});

describe("Card", () => {
  it("renders a titled section", () => {
    render(
      <Card title="Findings" eyebrow="Run" actions={<button type="button">Act</button>}>
        body
      </Card>,
    );
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText("Run")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Act" })).toBeInTheDocument();
    expect(screen.getByText("body")).toBeInTheDocument();
  });
});

describe("Badge", () => {
  it("renders text with a tone class", () => {
    render(<Badge tone="fail">denied</Badge>);
    expect(screen.getByText("denied").className).toContain("text-fail");
  });
});

describe("SeverityBadge", () => {
  it.each(SEVERITIES)("shows %s as text, not colour alone", (severity) => {
    render(<SeverityBadge severity={severity} />);
    const badge = screen.getByText(severity);
    expect(badge).toHaveAttribute("data-severity", severity);
    expect(badge).toHaveAttribute("title");
    expect(badge.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it("shows an optional count", () => {
    render(<SeverityBadge severity="HIGH" count={3} />);
    expect(screen.getByText("3")).toBeInTheDocument();
  });
});

describe("Button", () => {
  it("is disabled and busy while loading", async () => {
    const onClick = vi.fn();
    render(
      <Button loading onClick={onClick}>
        Save
      </Button>,
    );
    const button = screen.getByRole("button", { name: /save/i });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    await userEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("defaults to type=button so it never submits forms by accident", () => {
    render(<Button>Go</Button>);
    expect(screen.getByRole("button")).toHaveAttribute("type", "button");
  });
});

describe("TextField", () => {
  it("links label, hint and error to the input", () => {
    render(<TextField label="Target" hint="A domain" error="Invalid" />);
    const input = screen.getByLabelText("Target");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription("A domain Invalid");
  });
});

describe("Tabs", () => {
  const items = [
    { id: "findings", label: "Findings", content: <p>findings panel</p> },
    { id: "raw", label: "Raw", content: <p>raw panel</p> },
    { id: "log", label: "Log", content: <p>log panel</p> },
  ];

  it("follows the ARIA tabs pattern", async () => {
    render(<Tabs label="Result" items={items} />);
    expect(screen.getByRole("tablist", { name: "Result" })).toBeInTheDocument();
    const first = screen.getByRole("tab", { name: "Findings" });
    expect(first).toHaveAttribute("aria-selected", "true");
    expect(first).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("tab", { name: "Raw" })).toHaveAttribute("tabindex", "-1");
    expect(screen.getByRole("tabpanel")).toHaveTextContent("findings panel");
    expect(screen.getByRole("tabpanel")).toHaveAccessibleName("Findings");

    await userEvent.click(screen.getByRole("tab", { name: "Raw" }));
    expect(screen.getByRole("tabpanel")).toHaveTextContent("raw panel");
  });

  it("supports arrow, Home and End keys with wrap-around", async () => {
    render(<Tabs label="Result" items={items} />);
    await userEvent.click(screen.getByRole("tab", { name: "Findings" }));
    await userEvent.keyboard("{ArrowLeft}");
    expect(screen.getByRole("tab", { name: "Log" })).toHaveFocus();
    expect(screen.getByRole("tabpanel")).toHaveTextContent("log panel");
    await userEvent.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Findings" })).toHaveFocus();
    await userEvent.keyboard("{End}");
    expect(screen.getByRole("tab", { name: "Log" })).toHaveAttribute("aria-selected", "true");
    await userEvent.keyboard("{Home}");
    expect(screen.getByRole("tab", { name: "Findings" })).toHaveAttribute("aria-selected", "true");
  });

  it("can be controlled", async () => {
    const onChange = vi.fn();
    render(<Tabs label="Result" items={items} value="raw" onChange={onChange} />);
    await userEvent.click(screen.getByRole("tab", { name: "Log" }));
    expect(onChange).toHaveBeenCalledWith("log");
    // Still controlled by the prop.
    expect(screen.getByRole("tabpanel")).toHaveTextContent("raw panel");
  });
});

describe("Toast", () => {
  function Trigger({ tone }: { tone: "info" | "success" | "error" }) {
    const toast = useToast();
    return (
      <button
        type="button"
        onClick={() => toast.show({ tone, title: `${tone} title`, description: "details" })}
      >
        show
      </button>
    );
  }

  it("announces info politely and auto-dismisses", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(
      <ToastProvider>
        <Trigger tone="success" />
      </ToastProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "show" }));
    expect(screen.getByRole("status")).toHaveTextContent("success title");
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(screen.queryByText("success title")).not.toBeInTheDocument();
  });

  it("announces errors assertively and keeps them until dismissed", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(
      <ToastProvider>
        <Trigger tone="error" />
      </ToastProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "show" }));
    const alert = screen.getByRole("alert");
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(alert).toBeInTheDocument();
    await userEvent.click(within(alert).getByRole("button", { name: "Dismiss notification" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("throws a clear error outside the provider", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<Trigger tone="info" />)).toThrow(/ToastProvider/);
  });
});

describe("DataTable", () => {
  interface Row {
    id: string;
    name: string;
    port: number;
  }
  const rows: Row[] = [
    { id: "1", name: "ssh", port: 22 },
    { id: "2", name: "http", port: 80 },
    { id: "3", name: "dns", port: 53 },
  ];
  const columns: Column<Row>[] = [
    { id: "name", header: "Service", cell: (r) => r.name, sortValue: (r) => r.name },
    { id: "port", header: "Port", cell: (r) => r.port, sortValue: (r) => r.port },
  ];
  const firstColumn = () =>
    screen
      .getAllByRole("row")
      .slice(1)
      .map((row) => within(row).getAllByRole("cell")[0]!.textContent);

  it("renders a captioned table", () => {
    render(<DataTable caption="Open ports" columns={columns} rows={rows} getRowId={(r) => r.id} />);
    expect(screen.getByRole("table", { name: "Open ports" })).toBeInTheDocument();
    expect(firstColumn()).toEqual(["ssh", "http", "dns"]);
  });

  it("sorts with aria-sort, toggling direction", async () => {
    render(<DataTable caption="Ports" columns={columns} rows={rows} getRowId={(r) => r.id} />);
    await userEvent.click(screen.getByRole("button", { name: /port/i }));
    expect(screen.getByRole("columnheader", { name: /port/i })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
    expect(firstColumn()).toEqual(["ssh", "dns", "http"]);
    await userEvent.click(screen.getByRole("button", { name: /port/i }));
    expect(screen.getByRole("columnheader", { name: /port/i })).toHaveAttribute(
      "aria-sort",
      "descending",
    );
    expect(firstColumn()).toEqual(["http", "dns", "ssh"]);
  });

  it("activates rows by click and keyboard", async () => {
    const onRowClick = vi.fn();
    render(
      <DataTable
        caption="Ports"
        columns={columns}
        rows={rows}
        getRowId={(r) => r.id}
        onRowClick={onRowClick}
        rowActionLabel={(r) => `Open ${r.name}`}
      />,
    );
    await userEvent.click(screen.getByRole("row", { name: "Open http" }));
    expect(onRowClick).toHaveBeenLastCalledWith(rows[1]);
    screen.getByRole("row", { name: "Open dns" }).focus();
    await userEvent.keyboard("{Enter}");
    expect(onRowClick).toHaveBeenLastCalledWith(rows[2]);
  });

  it("shows empty and loading states", () => {
    const { rerender } = render(
      <DataTable
        caption="Ports"
        columns={columns}
        rows={[]}
        getRowId={(r) => r.id}
        emptyMessage="Nothing open"
      />,
    );
    expect(screen.getByText("Nothing open")).toBeInTheDocument();
    rerender(
      <DataTable caption="Ports" columns={columns} rows={[]} getRowId={(r) => r.id} loading />,
    );
    expect(screen.getByRole("status")).toBeInTheDocument();
  });
});

describe("JsonViewer", () => {
  it("renders untrusted strings as text, never as HTML", () => {
    const payload = {
      banner: "<script>window.__pwned = true</script>",
      link: "javascript:alert(1)",
      "<img src=x onerror=alert(1)>": 1,
    };
    const { container } = render(<JsonViewer value={payload} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(screen.getByText(/<script>window.__pwned = true<\/script>/)).toBeInTheDocument();
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined();
  });

  it("expands and collapses nested nodes", async () => {
    render(<JsonViewer value={{ outer: { inner: "deep value" } }} defaultExpandDepth={1} />);
    expect(screen.queryByText(/deep value/)).not.toBeInTheDocument();
    const toggle = screen.getByRole("button", { name: /expand outer/i });
    await userEvent.click(toggle);
    expect(screen.getByText(/deep value/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /collapse outer/i }));
    expect(screen.queryByText(/deep value/)).not.toBeInTheDocument();
  });

  it("bounds rendering of huge payloads", () => {
    const value = { big: "x".repeat(5000), list: Array.from({ length: 500 }, (_, i) => i) };
    render(<JsonViewer value={value} defaultExpandDepth={3} maxItems={10} maxStringLength={100} />);
    expect(screen.getByText(/\+4900 chars/)).toBeInTheDocument();
    expect(screen.getByText(/490 more not shown/)).toBeInTheDocument();
  });

  it("cuts off excessive nesting", () => {
    let value: unknown = "bottom";
    for (let i = 0; i < 30; i++) value = { n: value };
    render(<JsonViewer value={value} defaultExpandDepth={50} maxDepth={5} />);
    expect(screen.getByText(/nested too deep/)).toBeInTheDocument();
    expect(screen.queryByText(/bottom/)).not.toBeInTheDocument();
  });

  it("copies the JSON to the clipboard", async () => {
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText");
    render(<JsonViewer value={{ a: 1 }} />);
    await user.click(screen.getByRole("button", { name: "Copy JSON" }));
    expect(writeText).toHaveBeenCalledWith('{\n  "a": 1\n}');
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });
});

describe("Drawer", () => {
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button type="button" onClick={() => setOpen(true)}>
          open details
        </button>
        <Drawer open={open} title="Event #7" onClose={() => setOpen(false)}>
          <button type="button">inside</button>
        </Drawer>
      </>
    );
  }

  it("is a labelled modal dialog that closes on Escape and restores focus", async () => {
    render(<Harness />);
    const opener = screen.getByRole("button", { name: "open details" });
    await userEvent.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Event #7" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("traps Tab inside the dialog", async () => {
    render(<Harness />);
    await userEvent.click(screen.getByRole("button", { name: "open details" }));
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "inside" })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
  });
});
