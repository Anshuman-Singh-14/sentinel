import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { useMemo, useState } from "react";
import type { ReactNode } from "react";

import { cn } from "./cn";
import { Spinner } from "./Spinner";

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Provide to make the column sortable (client-side). */
  sortValue?: (row: T) => string | number | null | undefined;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  getRowId: (row: T) => string;
  /** Visually hidden table caption; screen readers announce it. */
  caption: string;
  loading?: boolean;
  emptyMessage?: ReactNode;
  /** Makes rows activatable by click, Enter or Space. */
  onRowClick?: (row: T) => void;
  /** Accessible label for the row action, e.g. "Show event details". */
  rowActionLabel?: (row: T) => string;
  selectedRowId?: string | null;
}

type SortState = { columnId: string; direction: "asc" | "desc" } | null;

function compare(a: string | number | null | undefined, b: string | number | null | undefined) {
  if (a === b) return 0;
  if (a === null || a === undefined) return 1;
  if (b === null || b === undefined) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b));
}

/**
 * Semantic table with optional client-side sorting (aria-sort on headers) and
 * keyboard-activatable rows. Server-side paging lives in the caller.
 */
export function DataTable<T>({
  columns,
  rows,
  getRowId,
  caption,
  loading = false,
  emptyMessage = "No data.",
  onRowClick,
  rowActionLabel,
  selectedRowId,
}: DataTableProps<T>) {
  const [sort, setSort] = useState<SortState>(null);

  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const column = columns.find((c) => c.id === sort.columnId);
    if (!column?.sortValue) return rows;
    const getValue = column.sortValue;
    const sign = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => sign * compare(getValue(a), getValue(b)));
  }, [rows, columns, sort]);

  const toggleSort = (columnId: string) => {
    setSort((current) =>
      current?.columnId === columnId
        ? { columnId, direction: current.direction === "asc" ? "desc" : "asc" }
        : { columnId, direction: "asc" },
    );
  };

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full border-collapse text-left text-xs">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-panel-raised text-muted">
          <tr>
            {columns.map((column) => {
              const active = sort?.columnId === column.id;
              const ariaSort = active
                ? sort.direction === "asc"
                  ? "ascending"
                  : "descending"
                : undefined;
              return (
                <th
                  key={column.id}
                  scope="col"
                  aria-sort={ariaSort}
                  className={cn(
                    "border-b border-border px-3 py-2 font-semibold tracking-wider uppercase",
                    column.className,
                  )}
                >
                  {column.sortValue ? (
                    <button
                      type="button"
                      onClick={() => toggleSort(column.id)}
                      className="inline-flex items-center gap-1 uppercase hover:text-text"
                    >
                      {column.header}
                      {active ? (
                        sort.direction === "asc" ? (
                          <ArrowUp size={12} aria-hidden="true" />
                        ) : (
                          <ArrowDown size={12} aria-hidden="true" />
                        )
                      ) : (
                        <ArrowUpDown size={12} aria-hidden="true" className="opacity-50" />
                      )}
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {loading && rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-center">
                <Spinner />
              </td>
            </tr>
          ) : sortedRows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-center text-muted">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            sortedRows.map((row) => {
              const id = getRowId(row);
              const interactive = Boolean(onRowClick);
              return (
                <tr
                  key={id}
                  tabIndex={interactive ? 0 : undefined}
                  aria-label={interactive ? rowActionLabel?.(row) : undefined}
                  aria-current={selectedRowId === id ? "true" : undefined}
                  onClick={interactive ? () => onRowClick?.(row) : undefined}
                  onKeyDown={
                    interactive
                      ? (event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            onRowClick?.(row);
                          }
                        }
                      : undefined
                  }
                  className={cn(
                    "border-b border-border last:border-b-0",
                    interactive && "cursor-pointer hover:bg-panel-raised",
                    selectedRowId === id && "bg-accent/10",
                  )}
                >
                  {columns.map((column) => (
                    <td key={column.id} className={cn("px-3 py-2 align-top", column.className)}>
                      {column.cell(row)}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
