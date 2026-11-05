/**
 * Tests for `readableFailure` in `@/api/client`.
 *
 * `request` throws `ApiError` carrying the RAW response body, so an error
 * surfaced verbatim reads
 * `{"error":"anchor offset does not name an addressable byte",...}`. Unwrapping
 * the envelope is the difference between a note the analyst can act on and a
 * JSON blob in the middle of the UI — which is why this lives beside `ApiError`
 * rather than as a private copy in each store that reverts to the raw body.
 */

import { describe, it, expect } from "vitest";

import { ApiError, readableFailure } from "@/api/client";

describe("readableFailure", () => {
  it("unwraps the backend's `error` envelope", () => {
    const err = new ApiError(
      400,
      '{"error":"anchor offset does not name an addressable byte","category":"coordinate"}',
    );

    expect(readableFailure(err)).toBe("anchor offset does not name an addressable byte");
  });

  it("falls back to `detail`, then to `message`", () => {
    expect(readableFailure(new ApiError(422, '{"detail":"dump_paths is required"}'))).toBe(
      "dump_paths is required",
    );
    expect(readableFailure(new ApiError(500, '{"message":"boom"}'))).toBe("boom");
  });

  it("prefers `error` when several envelope fields are present", () => {
    const err = new ApiError(400, '{"error":"first","detail":"second","message":"third"}');

    expect(readableFailure(err)).toBe("first");
  });

  it("skips an empty envelope field rather than surfacing a blank note", () => {
    expect(readableFailure(new ApiError(400, '{"error":"   ","detail":"the real one"}'))).toBe(
      "the real one",
    );
  });

  it("leaves a plain sentence alone", () => {
    expect(readableFailure(new Error("Network request failed"))).toBe(
      "Network request failed",
    );
  });

  /** Not JSON after all — the raw text is the best we have, so keep it. */
  it("returns the raw body when the envelope will not parse", () => {
    expect(readableFailure(new ApiError(502, "{not json"))).toBe("{not json");
  });

  it("returns the raw body when the JSON carries no message field", () => {
    expect(readableFailure(new ApiError(400, '{"code":17}'))).toBe('{"code":17}');
  });

  it("unwraps a `{code, message}` object under `detail`", () => {
    const body = '{"detail":{"code":"provider_error","message":"the provider refused the API key"}}';
    expect(readableFailure(new ApiError(502, body))).toBe("the provider refused the API key");
  });

  it("stringifies a non-Error rejection", () => {
    expect(readableFailure("plain string")).toBe("plain string");
    expect(readableFailure(42)).toBe("42");
  });
});
