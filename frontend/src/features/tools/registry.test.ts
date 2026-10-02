import { Wrench } from "lucide-react";
import { describe, expect, it } from "vitest";

import { ECHO_TOOL } from "../../test/utils";
import type { ToolDescriptor } from "../../types/api";
import { LOCAL_TOOLS, buildToolNavigation } from "./registry";

const unknownActive: ToolDescriptor = {
  ...ECHO_TOOL,
  tool_id: "brand_new_tool",
  name: "Brand New Tool",
  category: "WEB",
  is_active: true,
  required_role: "admin",
};

describe("buildToolNavigation", () => {
  it("always lists the local utilities first, marked as local-only", () => {
    const [local] = buildToolNavigation([], "viewer");
    expect(local?.id).toBe("local");
    expect(local?.note).toMatch(/browser only/i);
    expect(local?.items.map((i) => i.label)).toEqual(LOCAL_TOOLS.map((t) => t.name));
  });

  it("links every shipped local tool under /local/", () => {
    const [local] = buildToolNavigation([], "viewer");
    for (const item of local!.items) {
      expect(item.disabled).toBe(false);
      expect(item.tag).toBeUndefined();
      expect(item.path).toMatch(/^\/local\/[a-z]+$/);
    }
  });

  it("gives every local tool a lazy loader that resolves to a component", async () => {
    for (const tool of LOCAL_TOOLS) {
      const module = await tool.load();
      expect(typeof module.default).toBe("function");
    }
  });

  it("adds backend tools grouped by category in a fixed order", () => {
    const groups = buildToolNavigation([ECHO_TOOL, unknownActive], "admin");
    expect(groups.map((g) => g.label)).toEqual(["Local utilities", "Web security", "Diagnostics"]);
    const echo = groups[2]!.items[0]!;
    expect(echo).toMatchObject({ label: "Echo", path: "/tools/echo", locked: false });
  });

  it("shows an unknown backend tool with a fallback icon (registry-driven, no code change)", () => {
    const groups = buildToolNavigation([unknownActive], "admin");
    const item = groups[1]!.items[0]!;
    expect(item.icon).toBe(Wrench);
    expect(item.tag).toBe("active");
    expect(item.path).toBe("/tools/brand_new_tool");
  });

  it("marks tools above the user's role as locked", () => {
    const groups = buildToolNavigation([ECHO_TOOL, unknownActive], "viewer");
    const items = groups.slice(1).flatMap((g) => g.items);
    expect(items.every((i) => i.locked)).toBe(true);
  });

  it("URL-encodes tool ids in paths", () => {
    const groups = buildToolNavigation([{ ...ECHO_TOOL, tool_id: "a/b" }], "admin");
    expect(groups[1]!.items[0]!.path).toBe("/tools/a%2Fb");
  });
});
