import { Fragment, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { parseInline } from "@/utils/markdown";

/**
 * `[seen]`, or a tag with its citation inside the same brackets as models
 * often write it: `[seen: get_processes, Location: /x.msl]`. The citation is
 * bounded (one line, no `]`, at most 300 chars) so a stray `[` cannot swallow text.
 */
const TAG = /\[(seen|inferred|unknown)(?:[:\s]([^\]\n]{0,300}))?\]/gi;
const TAG_COLOR: Record<string, string> = {
  seen: "var(--md-accent-green)",
  inferred: "var(--md-accent-blue)",
  unknown: "var(--md-text-muted)",
};

/** Assistant text: inline markdown (as React nodes, never HTML) with [seen]/[inferred]/[unknown] as badges. */
export function EvidenceText({ text }: { text: string }) {
  const { t } = useTranslation("agent");
  const renderLine = (line: string): ReactNode[] => {
    const out: ReactNode[] = [];
    let last = 0;
    for (const m of line.matchAll(TAG)) {
      const at = m.index ?? 0;
      const kind = m[1].toLowerCase();
      const citation = m[2]?.trim();
      if (at > last) out.push(...parseInline(line.slice(last, at)));
      out.push(
        <span
          key={`tag-${at}`}
          data-testid={`evidence-${kind}`}
          className="mx-0.5 px-1 rounded border text-[10px] uppercase align-middle"
          style={{ color: TAG_COLOR[kind], borderColor: TAG_COLOR[kind] }}
        >
          {t(`evidence.${kind}`)}
        </span>,
      );
      if (citation) {
        out.push(
          <span
            key={`cite-${at}`}
            data-testid="evidence-citation"
            className="mr-0.5"
            style={{ color: "var(--md-text-muted)" }}
          >
            {citation}
          </span>,
        );
      }
      last = at + m[0].length;
    }
    if (last < line.length) out.push(...parseInline(line.slice(last)));
    return out;
  };
  return (
    <div className="text-xs whitespace-pre-wrap break-words">
      {text.split("\n").map((line, i) => (
        <Fragment key={i}>
          {i > 0 && <br />}
          {renderLine(line)}
        </Fragment>
      ))}
    </div>
  );
}
