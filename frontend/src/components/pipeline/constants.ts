/**
 * Magic-string constants for pipeline artifacts + stage names.
 *
 * These match the names the backend registers in
 * ``engine/pipeline_runner.py``. Any new artifact the worker produces
 * must land here first so the UI has a single place to key off.
 */

export const ARTIFACT_NAMES = {
  CONSENSUS_VARIANCE: "consensus_variance",
  CONSENSUS_REFERENCE: "consensus_reference",
  CANDIDATES: "candidates",
  HITS: "hits",
  NSWEEP_JSON: "nsweep_json",
  NSWEEP_MD: "nsweep_md",
  NSWEEP_HTML: "nsweep_html",
  VOL3_PLUGIN: "vol3_plugin",
  /** Standalone `.yar` sibling of the plugin; loadable by yara.compile. */
  VOL3_YARA_RULE: "vol3_yara_rule",
} as const;

/**
 * The stage event carries only verdict names, so their outcome has to be known
 * here. The strings are the stable ones of `engine/scudo_candidates.py`.
 */
export const SCUDO_KEPT_VERDICTS: ReadonlySet<string> = new Set([
  "signature_unique",
  "dynamic_residue",
  "dynamic_candidate",
]);
export const SCUDO_NOT_JUDGED_VERDICTS: ReadonlySet<string> = new Set(["missing"]);

/** Names surfaced in primary result tabs; everything else is "Raw". */
export const PRIMARY_ARTIFACT_NAMES: ReadonlySet<string> = new Set([
  ARTIFACT_NAMES.VOL3_PLUGIN,
  ARTIFACT_NAMES.NSWEEP_HTML,
]);
