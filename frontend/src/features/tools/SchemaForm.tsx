/**
 * A form generated from a tool's parameter JSON Schema (`GET /api/v1/tools`),
 * so a new backend tool gets a working form with no frontend code
 * (CLAUDE.md rule 9).
 *
 * Supported: a flat object of string (with enum, minLength, maxLength,
 * pattern), integer/number (minimum, maximum) and boolean properties, plus
 * `required`, `default`, `description` and `examples`. Anything else is
 * reported as unsupported rather than guessed at. `readOnly` properties are
 * set by the server (e.g. an upload's file name) and are not shown.
 *
 * Client checks are for fast feedback only. The backend validates again and
 * its 422 errors (`loc: ["params", field]`) are shown next to the field.
 */

import { useId, useState } from "react";
import type { FormEvent } from "react";

import { Button, TextField, cn } from "../../components/ui";

interface PropertySchema {
  type?: string;
  title?: string;
  description?: string;
  default?: unknown;
  enum?: unknown[];
  examples?: unknown[];
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  readOnly?: boolean;
}

export interface ObjectSchema {
  type?: string;
  properties?: Record<string, PropertySchema>;
  required?: string[];
}

type FieldKind = "string" | "enum" | "integer" | "number" | "boolean";

export interface FieldSpec {
  name: string;
  kind: FieldKind;
  label: string;
  schema: PropertySchema;
  required: boolean;
}

function humanise(name: string): string {
  const spaced = name.replace(/_/g, " ");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/** Map the schema to field specs, or explain why it cannot be rendered. */
export function fieldsFromSchema(schema: ObjectSchema): FieldSpec[] | { unsupported: string } {
  if (schema.type !== "object") return { unsupported: "the parameters are not an object" };
  const required = new Set(schema.required ?? []);
  const fields: FieldSpec[] = [];
  for (const [name, prop] of Object.entries(schema.properties ?? {})) {
    if (prop.readOnly) continue;
    let kind: FieldKind;
    if (prop.enum && prop.type === "string") kind = "enum";
    else if (prop.type === "string") kind = "string";
    else if (prop.type === "integer") kind = "integer";
    else if (prop.type === "number") kind = "number";
    else if (prop.type === "boolean") kind = "boolean";
    else return { unsupported: `field "${name}" has an unsupported type` };
    fields.push({
      name,
      kind,
      label: prop.title ?? humanise(name),
      schema: prop,
      required: required.has(name),
    });
  }
  return fields;
}

type Values = Record<string, string | boolean>;

export function initialValues(fields: FieldSpec[]): Values {
  const values: Values = {};
  for (const field of fields) {
    const d = field.schema.default;
    if (field.kind === "boolean") values[field.name] = typeof d === "boolean" ? d : false;
    else values[field.name] = d === undefined || d === null ? "" : String(d);
  }
  return values;
}

/** Client-side checks mirroring the schema. Returns field -> message. */
export function validate(fields: FieldSpec[], values: Values): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const field of fields) {
    const raw = values[field.name];
    if (field.kind === "boolean") continue;
    const value = typeof raw === "string" ? raw.trim() : "";
    const s = field.schema;
    if (!value) {
      if (field.required) errors[field.name] = "Required.";
      continue;
    }
    if (field.kind === "integer" || field.kind === "number") {
      const n = Number(value);
      if (!Number.isFinite(n) || (field.kind === "integer" && !Number.isInteger(n))) {
        errors[field.name] = field.kind === "integer" ? "Enter a whole number." : "Enter a number.";
      } else if (s.minimum !== undefined && n < s.minimum) {
        errors[field.name] = `Must be at least ${s.minimum}.`;
      } else if (s.maximum !== undefined && n > s.maximum) {
        errors[field.name] = `Must be at most ${s.maximum}.`;
      }
    } else if (field.kind === "string") {
      if (s.minLength !== undefined && value.length < s.minLength) {
        errors[field.name] = `Must be at least ${s.minLength} characters.`;
      } else if (s.maxLength !== undefined && value.length > s.maxLength) {
        errors[field.name] = `Must be at most ${s.maxLength} characters.`;
      }
    }
  }
  return errors;
}

/** Convert form values to the JSON the API expects; empty optionals are omitted. */
export function toParams(fields: FieldSpec[], values: Values): Record<string, unknown> {
  const params: Record<string, unknown> = {};
  for (const field of fields) {
    const raw = values[field.name];
    if (field.kind === "boolean") {
      params[field.name] = Boolean(raw);
      continue;
    }
    const value = typeof raw === "string" ? raw.trim() : "";
    if (!value) continue;
    params[field.name] =
      field.kind === "integer" || field.kind === "number" ? Number(value) : value;
  }
  return params;
}

interface SchemaFormProps {
  schema: ObjectSchema;
  submitLabel: string;
  busy?: boolean;
  disabled?: boolean;
  /** Server-side errors keyed by field name. */
  serverErrors?: Record<string, string>;
  onSubmit: (params: Record<string, unknown>) => void;
}

export function SchemaForm({
  schema,
  submitLabel,
  busy,
  disabled,
  serverErrors = {},
  onSubmit,
}: SchemaFormProps) {
  const parsed = fieldsFromSchema(schema);
  const fields = Array.isArray(parsed) ? parsed : [];
  const [values, setValues] = useState<Values>(() => initialValues(fields));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const baseId = useId();

  if (!Array.isArray(parsed)) {
    return (
      <p role="alert" className="text-sm text-warn">
        This tool's form cannot be generated: {parsed.unsupported}.
      </p>
    );
  }

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const found = validate(fields, values);
    setErrors(found);
    if (Object.keys(found).length === 0) onSubmit(toParams(fields, values));
  };

  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-4">
      {fields.map((field) => {
        const error = errors[field.name] ?? serverErrors[field.name];
        const s = field.schema;
        const example = s.examples?.[0];
        const label = `${field.label}${field.required ? "" : " (optional)"}`;
        if (field.kind === "boolean") {
          return (
            <label key={field.name} className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 accent-accent"
                checked={Boolean(values[field.name])}
                onChange={(e) => setValues((v) => ({ ...v, [field.name]: e.target.checked }))}
              />
              <span>
                {field.label}
                {s.description && <span className="block text-xs text-muted">{s.description}</span>}
              </span>
            </label>
          );
        }
        if (field.kind === "enum") {
          const id = `${baseId}-${field.name}`;
          return (
            <div key={field.name} className="flex flex-col gap-1.5">
              <label
                htmlFor={id}
                className="text-xs font-semibold tracking-wider text-muted uppercase"
              >
                {label}
              </label>
              <select
                id={id}
                value={String(values[field.name])}
                onChange={(e) => setValues((v) => ({ ...v, [field.name]: e.target.value }))}
                className={cn(
                  "rounded border bg-surface px-3 py-2 text-sm focus:border-accent focus:outline-none",
                  error ? "border-fail" : "border-border-strong",
                )}
              >
                {!field.required && <option value="">—</option>}
                {s.enum!.map((option) => (
                  <option key={String(option)} value={String(option)}>
                    {String(option)}
                  </option>
                ))}
              </select>
              {s.description && <p className="text-xs text-muted">{s.description}</p>}
              {error && <p className="text-xs text-fail">{error}</p>}
            </div>
          );
        }
        const numeric = field.kind === "integer" || field.kind === "number";
        return (
          <TextField
            key={field.name}
            label={label}
            name={field.name}
            type={numeric ? "number" : "text"}
            inputMode={field.kind === "integer" ? "numeric" : undefined}
            min={numeric ? s.minimum : undefined}
            max={numeric ? s.maximum : undefined}
            step={field.kind === "integer" ? 1 : undefined}
            maxLength={!numeric ? s.maxLength : undefined}
            placeholder={example !== undefined ? String(example) : undefined}
            autoComplete="off"
            spellCheck={false}
            hint={s.description}
            error={error}
            value={String(values[field.name])}
            onChange={(e) => setValues((v) => ({ ...v, [field.name]: e.target.value }))}
          />
        );
      })}
      <div>
        <Button type="submit" loading={busy} disabled={disabled}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
