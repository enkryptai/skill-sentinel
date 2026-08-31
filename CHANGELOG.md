# Changelog

All notable changes to skill-sentinel are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## [0.4.0]

### Added — provider & model fallback

Each agent can now fall back across models and providers when a call fails with a
transient or provider-level error (rate limit, quota exhausted, `5xx`,
connection, or auth); non-retryable errors are not retried.

- **`FALLBACK_MODELS`** — comma-separated `provider/model` list tried in order
  after the primary (e.g. `anthropic/claude-<model-id>,groq/llama-3.3-70b-versatile`).
  Fallbacks may be a different provider than the primary; each authenticates with
  its provider's standard key env var. A fallback whose provider isn't installed
  is skipped with a warning and never breaks the primary.
- **`PRIMARY_MODEL`** — sets the primary model when `OPENAI_MODEL_NAME` is unset,
  allowing a non-OpenAI primary.

With no `FALLBACK_MODELS` set, behaviour is unchanged (a single primary model).

### Fixed

- Report parsing now tolerates a JSON report wrapped in ```` ```json ```` fences
  or surrounded by prose (common with open-weight fallback models) by extracting
  the outermost `{ … }` object, instead of failing on the leading fence.

### Changed

- The `crewai` dependency now includes the `litellm`, `anthropic`, and
  `google-genai` extras (`crewai[tools,litellm,anthropic,google-genai]`) so
  OpenAI, Anthropic, and Gemini work as native providers and the long tail of
  providers routes through LiteLLM out of the box.

## [0.3.0]

### Added — report metadata computed by the scanner

The report now includes deterministic, code-computed fields about the scanned
skill (injected in the same finalize step as `token_usage`, not produced by the
LLM):

- **`skill_name`** — parsed from the `SKILL.md` YAML frontmatter `name:` (falls
  back to the skill directory's basename). Callers no longer need to supply it.
- **`content_hash`** — `sha256` over **all files** in the skill directory
  (`SKILL.md` plus every supporting script/reference/binary), hashed in sorted
  relative-path order. Unlike a `SKILL.md`-only hash, this changes if *any* file
  changes, so it is a reliable change/dedup key for the full skill package.
- **`scan_duration`** — `{seconds, display}`, measured as the wall-clock time of
  the scan (previously not emitted).

Additive, backward-compatible: no changes to inputs, the CLI, dependencies, or
existing report fields.

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
