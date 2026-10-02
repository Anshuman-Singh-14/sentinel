import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { fieldsFromSchema, initialValues, toParams, validate } from "./SchemaForm";
import type { FieldSpec, ObjectSchema } from "./SchemaForm";
import { SchemaForm } from "./SchemaForm";

// The JSON Schemas the backend actually publishes (Pydantic v2 output).
const DNS_SCHEMA: ObjectSchema = {
  type: "object",
  required: ["domain"],
  properties: {
    domain: {
      type: "string",
      title: "Domain",
      description: "Domain to investigate, e.g. example.com.",
      examples: ["example.com"],
      maxLength: 253,
    },
    include_reverse: {
      type: "boolean",
      title: "Include Reverse",
      default: true,
      description: "Also look up reverse DNS.",
    },
  },
};

const ECHO_SCHEMA: ObjectSchema = {
  type: "object",
  required: ["message"],
  properties: {
    message: { type: "string", title: "Message", minLength: 1, maxLength: 500 },
    repeat: { type: "integer", title: "Repeat", default: 1, minimum: 1, maximum: 5 },
    mode: { type: "string", enum: ["fast", "slow"], title: "Mode" },
  },
};

describe("schema mapping", () => {
  it("maps supported property types", () => {
    const fields = fieldsFromSchema(ECHO_SCHEMA) as FieldSpec[];
    expect(fields.map((f) => [f.name, f.kind, f.required])).toEqual([
      ["message", "string", true],
      ["repeat", "integer", false],
      ["mode", "enum", false],
    ]);
  });

  it("refuses schemas it cannot render faithfully", () => {
    expect(fieldsFromSchema({ type: "array" })).toEqual({ unsupported: expect.any(String) });
    expect(fieldsFromSchema({ type: "object", properties: { x: { type: "array" } } })).toEqual({
      unsupported: 'field "x" has an unsupported type',
    });
  });

  it("applies defaults", () => {
    const fields = fieldsFromSchema(DNS_SCHEMA) as FieldSpec[];
    expect(initialValues(fields)).toEqual({ domain: "", include_reverse: true });
  });

  it("validates required, lengths and numeric bounds", () => {
    const fields = fieldsFromSchema(ECHO_SCHEMA) as FieldSpec[];
    expect(validate(fields, { message: " ", repeat: "9", mode: "" })).toEqual({
      message: "Required.",
      repeat: "Must be at most 5.",
    });
    expect(validate(fields, { message: "hi", repeat: "1.5", mode: "" })).toEqual({
      repeat: "Enter a whole number.",
    });
    expect(validate(fields, { message: "x".repeat(501), repeat: "", mode: "" })).toEqual({
      message: "Must be at most 500 characters.",
    });
  });

  it("builds typed params and omits empty optionals", () => {
    const fields = fieldsFromSchema(ECHO_SCHEMA) as FieldSpec[];
    expect(toParams(fields, { message: "  hi ", repeat: "3", mode: "" })).toEqual({
      message: "hi",
      repeat: 3,
    });
  });
});

describe("SchemaForm", () => {
  it("renders labelled inputs with hints and submits typed params", async () => {
    const onSubmit = vi.fn();
    render(<SchemaForm schema={DNS_SCHEMA} submitLabel="Run" onSubmit={onSubmit} />);
    const domain = screen.getByLabelText("Domain");
    expect(domain).toHaveAttribute("placeholder", "example.com");
    expect(domain).toHaveAccessibleDescription("Domain to investigate, e.g. example.com.");
    expect(screen.getByLabelText(/include reverse/i)).toBeChecked();

    await userEvent.type(domain, "example.org");
    await userEvent.click(screen.getByLabelText(/include reverse/i));
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(onSubmit).toHaveBeenCalledWith({ domain: "example.org", include_reverse: false });
  });

  it("blocks submission and shows client-side errors", async () => {
    const onSubmit = vi.fn();
    render(<SchemaForm schema={ECHO_SCHEMA} submitLabel="Run" onSubmit={onSubmit} />);
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Message")).toHaveAccessibleDescription("Required.");
  });

  it("shows server-side errors next to the field", () => {
    render(
      <SchemaForm
        schema={DNS_SCHEMA}
        submitLabel="Run"
        onSubmit={vi.fn()}
        serverErrors={{ domain: '".internal" names are reserved' }}
      />,
    );
    expect(screen.getByLabelText("Domain")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText('".internal" names are reserved')).toBeInTheDocument();
  });

  it("renders enums as selects and marks optional fields", () => {
    render(<SchemaForm schema={ECHO_SCHEMA} submitLabel="Run" onSubmit={vi.fn()} />);
    expect(screen.getByLabelText("Mode (optional)").tagName).toBe("SELECT");
    expect(screen.getByLabelText("Repeat (optional)")).toHaveAttribute("type", "number");
  });

  it("explains an unsupported schema", () => {
    render(<SchemaForm schema={{ type: "array" }} submitLabel="Run" onSubmit={vi.fn()} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/cannot be generated/);
  });
});
