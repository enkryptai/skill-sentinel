# Changelog

All notable changes to skill-sentinel are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## [0.2.0]

### Changed — finding calibration (especially for reasoning/mini models)

Hardened the analysis prompts to cut false positives without weakening real
threat detection. Some models (e.g. `gpt-5.4-mini`) were over-flagging normal,
disclosed agent-skill behavior (bounded retries, documented API/AI calls,
verbose-but-honest descriptions, internal file/log reads) as validated findings
and inflating the overall verdict. This release makes the "flag THREATS, not
normal behavior" intent explicit and enforceable.

- **`data/threat_categories.md`**: added an explicit **Threat Gate** — a candidate
  is a real threat only if it shows exfiltration, injection/execution,
  concealment/mismatch, or malware; otherwise it is a false positive and must not
  raise the verdict. Clarified that each category's "Default Severity" applies only
  when malicious intent is confirmed. Added per-category "NOT a threat"
  disqualifiers for `transitive_trust_abuse`, `data_exfiltration`,
  `skill_discovery_abuse`, `autonomy_abuse`, and `cross_context_bridging`, and
  expanded the "What NOT to Flag" list.
- **`config/tasks.yaml`** (report synthesis): replaced the soft "filter false
  positives" step with a mandatory per-finding threat gate; require severity to be
  set from confirmed malicious impact (not the category default); added an explicit
  rule that LOW is not an escape hatch for disclosed/benign behavior; added an
  output-integrity rule (an item may not appear in both `validated_findings` and
  `false_positives`, and evidence snippets must be verbatim); and added verdict
  calibration (SUSPICIOUS/MALICIOUS only when a finding survives the gate at
  MEDIUM+ with concrete malicious intent).

### Changed — default model

- The default model is now **`gpt-5.4-mini`** (previously `gpt-4.1`), applied to
  the CLI (`--model` / `OPENAI_MODEL_NAME`) and the library `scan()` when no model
  is specified. The calibration above is what makes this default reliable. Override
  with `-m/--model` or `OPENAI_MODEL_NAME` as before.

No API-signature, dependency, or report-schema changes. The `scan()` and
`skill-sentinel scan` interfaces are unchanged.

## [0.1.2]

- Baseline release.
