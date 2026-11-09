/**
 * Reduction-method choice on the thresholds stage.
 *
 * The positional consensus compares the same byte position across dumps. After
 * an Android cold boot Scudo has placed every allocation somewhere else, so
 * those positions hold unrelated bytes and the Scudo method pairs heap chunks
 * instead.
 *
 * Choosing it also clears `emit` and `nsweep`, because the server refuses both
 * for this method.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { ScudoParams } from "@/api/pipeline";
import { DEFAULT_KEY_SIZES, DEFAULT_SCUDO, usePipelineStore } from "@/stores/pipeline-store";
import { parseNValues } from "@/utils/n-values";

const HEADING_CLASS = "md-text-accent font-semibold text-xs uppercase tracking-wide";

export function ScudoMethodPanel() {
  const { t } = useTranslation("pipeline");
  const scudo = usePipelineStore((s) => s.form.scudo);
  const bruteForce = usePipelineStore((s) => s.form.bruteForce);
  const updateForm = usePipelineStore((s) => s.updateForm);
  // Free text so a half-typed list ("32,") need not round-trip through numbers.
  const [keySizesText, setKeySizesText] = useState(() => (bruteForce.key_sizes ?? [32]).join(","));

  const selectScudo = (): void => {
    updateForm({ scudo: scudo ?? DEFAULT_SCUDO, emit: null, nsweep: null });
  };
  const selectPositional = (): void => {
    updateForm({ scudo: null, bruteForce: { ...bruteForce, key_sizes: DEFAULT_KEY_SIZES } });
    setKeySizesText(DEFAULT_KEY_SIZES.join(","));
  };
  const selectAllocator = (allocator: ScudoParams["allocator"]): void => {
    updateForm({ scudo: { allocator } });
  };

  return (
    <fieldset className="md-panel p-3 space-y-2" data-testid="pipeline-method">
      <legend className={`${HEADING_CLASS} px-1`}>{t("stages.thresholds.method.title")}</legend>
      <label className="flex items-start gap-2 text-xs">
        <input
          type="radio"
          name="pipeline-method"
          checked={scudo === null}
          onChange={selectPositional}
        />
        <span>
          <span className="md-text-secondary">{t("stages.thresholds.method.positional")}</span>
          <span className="block text-[10px] md-text-muted">
            {t("stages.thresholds.method.positionalHint")}
          </span>
        </span>
      </label>
      <label className="flex items-start gap-2 text-xs">
        <input
          type="radio"
          name="pipeline-method"
          data-testid="pipeline-method-scudo"
          checked={scudo !== null}
          onChange={selectScudo}
        />
        <span>
          <span className="md-text-secondary">{t("stages.thresholds.method.scudo")}</span>
          <span className="block text-[10px] md-text-muted">
            {t("stages.thresholds.method.scudoHint")}
          </span>
        </span>
      </label>

      {scudo !== null && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          <fieldset className="space-y-1">
            <legend className="text-xs md-text-secondary">
              {t("stages.thresholds.method.allocatorTitle")}
            </legend>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="radio"
                name="pipeline-scudo-allocator"
                checked={scudo.allocator === "auto"}
                onChange={() => selectAllocator("auto")}
              />
              <span className="md-text-secondary">{t("stages.thresholds.method.allocatorAuto")}</span>
            </label>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="radio"
                name="pipeline-scudo-allocator"
                data-testid="pipeline-scudo-force"
                checked={scudo.allocator === "scudo"}
                onChange={() => selectAllocator("scudo")}
              />
              <span className="md-text-secondary">{t("stages.thresholds.method.allocatorForce")}</span>
            </label>
          </fieldset>
          <label className="block text-xs">
            <span className="md-text-secondary">{t("stages.thresholds.method.keySizes")}</span>
            <input
              type="text"
              value={keySizesText}
              data-testid="pipeline-scudo-key-sizes"
              onChange={(e) => {
                setKeySizesText(e.target.value);
                const parsed = parseNValues(e.target.value);
                if (parsed.length > 0) updateForm({ bruteForce: { ...bruteForce, key_sizes: parsed } });
              }}
              className="mt-0.5 w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded font-mono"
            />
            <span className="block mt-0.5 text-[10px] md-text-muted">
              {t("stages.thresholds.method.keySizesHelp")}
            </span>
          </label>
        </div>
      )}
    </fieldset>
  );
}
