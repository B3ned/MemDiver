import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@/i18n";

import { EvidenceText } from "@/components/agent/EvidenceText";

describe("EvidenceText", () => {
  it("renders evidence tags as badges and keeps the surrounding text", () => {
    render(<EvidenceText text={"[seen] key at 0x10\nnext [inferred] guess [unknown]"} />);
    expect(screen.getByTestId("evidence-seen")).toHaveTextContent("seen");
    expect(screen.getByTestId("evidence-inferred")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-unknown")).toBeInTheDocument();
    expect(screen.getByText(/key at 0x10/)).toBeInTheDocument();
  });

  it("never turns markup into elements", () => {
    const { container } = render(<EvidenceText text={"<img src=x onerror=alert(1)> **bold**"} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img");
  });

  it("renders a tag with an in-bracket citation as a badge plus visible citation text", () => {
    render(<EvidenceText text={"pid 1234 [seen: get_processes, Location: /path/sample.msl]"} />);
    expect(screen.getByTestId("evidence-seen")).toHaveTextContent("seen");
    expect(screen.getByTestId("evidence-citation")).toHaveTextContent(
      "get_processes, Location: /path/sample.msl",
    );
    expect(screen.getByText(/pid 1234/)).toBeInTheDocument();
  });

  it("accepts whitespace as separator and a case-insensitive tag word", () => {
    render(<EvidenceText text={"x [Inferred from entropy] y"} />);
    expect(screen.getByTestId("evidence-inferred")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-citation")).toHaveTextContent("from entropy");
  });

  it("keeps the bare form unchanged with no citation element", () => {
    const { container } = render(<EvidenceText text={"key [seen] here"} />);
    expect(screen.getByTestId("evidence-seen")).toHaveTextContent("seen");
    expect(screen.queryByTestId("evidence-citation")).toBeNull();
    expect(container.textContent).toBe("key seen here");
  });

  it("does not badge non-tag brackets", () => {
    const { container } = render(<EvidenceText text={"[seenx] and [note: x] and [unseen]"} />);
    expect(container.querySelector("[data-testid^='evidence-']")).toBeNull();
    expect(container.textContent).toContain("[seenx]");
    expect(container.textContent).toContain("[note: x]");
  });

  it("does not match an over-long or newline-spanning citation", () => {
    const { container } = render(
      <EvidenceText text={`[seen: ${"a".repeat(301)}] [unknown: split\nline]`} />,
    );
    expect(container.querySelector("[data-testid^='evidence-']")).toBeNull();
  });

  it("renders several mixed tags in one text", () => {
    render(
      <EvidenceText
        text={"a [seen: read_hex, offset 0x10] b [inferred] c [unknown: no tool] d [seen]"}
      />,
    );
    expect(screen.getAllByTestId("evidence-seen")).toHaveLength(2);
    expect(screen.getByTestId("evidence-inferred")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-unknown")).toBeInTheDocument();
    const cites = screen.getAllByTestId("evidence-citation").map((n) => n.textContent);
    expect(cites).toEqual(["read_hex, offset 0x10", "no tool"]);
  });

  it("never turns markup inside a citation into elements", () => {
    const { container } = render(<EvidenceText text={"[seen: <img src=x onerror=alert(1)>]"} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByTestId("evidence-citation")).toHaveTextContent("<img src=x onerror=alert(1)>");
  });
});
