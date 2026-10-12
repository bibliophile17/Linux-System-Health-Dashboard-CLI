# Incident-analysis evaluation design

**Status of this document:** written *before* the analysis module and before any result was produced.
Changes after the freeze point (see "Freeze record" at the bottom) must be listed in "Amendments".

## What is being evaluated

`syshealth analyze` (module `syshealth/analysis.py`) takes the **existing** `diagnose` findings plus the raw evidence
and produces: a status, a ranked list of *possible* causes with a confidence label, supporting and contradicting
evidence, missing evidence, uncertainties and read-only next steps. It must not duplicate the diagnostic rules; it only
correlates and ranks what they report.

## Dataset (synthetic, labelled)

`eval/incidents.json`: each case records the **injected condition** (what the hypothetical fault is), the
**observable evidence** (a synthetic snapshot; `null` = metric unreadable), the **expected diagnosis**, and the
**uncertainty** that remains even if the diagnosis is right. Cases are split into:

* `dev`: may be used while building the analysis;
* `heldout`: written before the analysis existed and **run once** after the rules were settled on `dev`.

Categories: CPU saturation, memory pressure, low disk space, disk I/O saturation, network errors, process/service
crashes, process proliferation, connection-state build-up, unavailable metrics, conflicting evidence, insufficient
evidence, multiple simultaneous faults, and healthy hosts (including near-threshold and historic-only counters).

## Label schema

| Field | Meaning |
|---|---|
| `expected.status` | `healthy`, `diagnosed`, `multiple_issues`, `inconclusive` or `insufficient_data` |
| `expected.acceptable_primary` | causes that are correct as the **top-ranked** cause (empty when no cause should be asserted) |
| `expected.valid_causes` | every cause genuinely present in the injected condition, including consequences |
| `expected.required_in_top3` | causes that must all appear in the top three |
| `expected.max_confidence` | the highest confidence the evidence justifies: `weak`, `moderate` or `strong` |
| `expected.uncertainty_keywords` | words that the stated uncertainties must mention (e.g. a metric that was unreadable) |

Cause labels: `cpu_saturation`, `memory_pressure`, `disk_space_exhaustion`, `disk_io_saturation`,
`network_interface_errors`, `service_failure`, `connection_state_buildup`, `process_proliferation`, `unexplained_load`.
`unexplained_load` is the explicit label for "load is high but no resource explains it".

Confidence order: `weak` < `moderate` < `strong`. Confidence is an **evidence-strength label, not a probability**.

## Metrics (defined now, computed by `python -m syshealth.analysis_eval`)

Let a *definite* case be one with `expected.status` in {`diagnosed`, `multiple_issues`}; an *abstain* case one with
{`inconclusive`, `insufficient_data`}; a *healthy* case one with `healthy`.

1. **Top-1 accuracy** = definite cases whose top-ranked cause is in `acceptable_primary` / definite cases.
2. **Top-3 accuracy** = definite cases where every `required_in_top3` cause is within the first three ranked causes /
   definite cases.
3. **Unsupported claims**, reported as three separate counts, never merged:
   * *assertive-claim precision failure*: a cause output with confidence >= `moderate` that is **not** in `valid_causes`
     (reported per assertive claim and per case);
   * *overclaim*: the top cause's confidence is higher than `expected.max_confidence`;
   * *untraceable support*: a supporting statement that does not appear verbatim in the evidence-derived observations
     the analysis itself lists.
4. **Correct abstention** = abstain cases where the output status is `inconclusive` or `insufficient_data` **and** no
   cause has confidence >= `moderate`. Also reported: **false abstention rate** (definite cases where the output
   abstained) and **false alarm rate** (healthy cases where the output was not `healthy`).
5. **Status exact match** (all cases), and **uncertainty coverage**: non-healthy cases whose output has at least one
   uncertainty, and cases whose uncertainties mention every `uncertainty_keywords` entry.

## Protocol

1. Freeze `eval/incidents.json` (SHA-256 recorded below) **before** implementing the analysis.
2. Implement the rules while looking at `dev` results only.
3. Run `heldout` once with the rules frozen; report it exactly as obtained. Failures are reported, not tuned away.
   Any later fix is listed under "Amendments" with the reason.
4. Compare against a **naive baseline** that ranks the existing findings by severity only (no corroboration, no
   contradiction handling, no abstention) so the report shows what the new logic adds over what `diagnose` already did.
5. No claim that rules beat or lose to an AI model is made: no model is evaluated here.

## Known limits of this evaluation (stated up front)

* The author of the cases is also the author of the rules. `heldout` limits tuning but is **not independent**, and
  the cases are small and synthetic. Results measure consistency, calibration of abstention and regression safety;
  they are **not** evidence of real-world diagnostic accuracy.
* With ~28 cases, a single case moves a percentage by several points; do not read small differences as meaningful.
* Synthetic evidence is cleaner than production telemetry.

## Freeze record

* `eval/incidents.json` SHA-256 at freeze: `37d1972f14331e6adc7218e80c9ccd4bb6ac49be21e305cb364e27f729155824`
  (also stored in `eval/incidents.sha256`; the evaluation script reports whether the dataset still matches it).
* 29 cases: 16 `dev`, 13 `heldout`. Expected statuses: 16 `diagnosed`, 2 `multiple_issues`, 4 `inconclusive`,
  2 `insufficient_data`, 5 `healthy`.
* Frozen **before** `syshealth/analysis.py` existed. The held-out labels were not changed after any result was seen.


## Results (rule-based/v1, run with `python -m syshealth.analysis_eval`)

Dev split was used while writing the rules. The held-out split was run **once**, after the rules were finished, and
nothing was changed afterwards. Committed output: `eval/results.json` (a test asserts a fresh run reproduces it).

| Metric (all 29 cases) | rule-based | naive severity-only |
|---|---|---|
| top-1 accuracy (18 definite cases) | 18/18 | 18/18 |
| top-3 accuracy | 18/18 | 18/18 |
| correct abstention (6 abstain cases) | 6/6 | 0/6 |
| false alarms (5 healthy cases) | 0/5 | 0/5 |
| unsupported assertive claims | 0/21 | 2/26 |
| overclaim cases | 0 | 5 |
| exact status match | 29/29 | 21/29 |

### How to read this honestly

* The cases and the rules were written by the same person (with the same assistant). 100% is therefore **not
  evidence of real-world accuracy**; it shows the rules are consistent with the author's own expectations,
  including the held-out ones. Held-out here means "not looked at while tuning", not "independent".
* Ranking the *obvious* cause is easy: the naive baseline also gets 100% top-1. The rule-based layer differs only in
  **calibration**: it abstains when evidence is thin or conflicting, caps confidence, orders cause before consequence,
  and avoids the naive baseline's overclaims.
* 29 synthetic cases is too few for percentages to mean anything beyond "no failures on these cases".
* Not tested: real hosts, concurrent faults beyond two, kernel versions, containers, cgroup limits.
* No language-model comparison exists. See "Ollama" in the README for why this matters.

## Amendments

(none)
