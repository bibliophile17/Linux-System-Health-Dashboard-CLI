# Incident-analysis evaluation protocol (written before the analyzer)

**Status of this document:** written and committed *before* any analyzer code existed. The metric definitions,
split policy and decision rule below were not changed after seeing results.

## What is being evaluated

Given the output of the existing diagnostics (`syshealth.diagnostics.Finding` list) plus a few raw evidence
facts (pressure, OOM counter, failed units), the analyzer must:

1. rank candidate **problem areas** (not proven root causes) by how well the evidence supports them,
2. say **"healthy"** when nothing current is wrong, and
3. **abstain** ("insufficient_evidence") when the evidence is too weak, too conflicting, or too incomplete.

Problem-area labels: `cpu_saturation`, `memory_pressure`, `disk_space_exhaustion`, `disk_io_saturation`,
`network_interface_errors`, `process_crash`, `connection_buildup`, `process_count_high`.
Statuses: `diagnosed`, `healthy`, `insufficient_evidence`.

## Data

`evaluation/incidents.json`: synthetic cases only. Each case records the **injected condition** (what a fault
would look like in words), the **observable evidence** (the numbers that encode it), the **expected diagnosis**
(`status`, `injected` causes, `primary_any_of`, tolerated `downstream_ok` effects) and the **uncertainty**
that should remain. Nothing is ever injected into a real host: cases are parameter sets turned into
`Evidence` objects.

Split policy:

* `dev` cases (14) may be used while building the analyzer.
* `heldout` cases (17) were written **before** the analyzer and are frozen by SHA-256
  (`evaluation/heldout.sha256`; a test fails if they change). The analyzer is evaluated on them **once**,
  after the analyzer code is final. Failures are reported, not tuned away. If a bug fix is made after that
  run, both before/after numbers are reported.

## Metrics (fixed in advance)

All counts are reported with their denominators; proportions get Wilson 95% intervals.

| id | metric | definition |
|---|---|---|
| M1 | top-1 accuracy | over cases expecting `diagnosed`: analyzer status is `diagnosed` **and** rank-1 cause is in `primary_any_of` |
| M2 | top-3 accuracy | same cases: status `diagnosed` **and** every `injected` cause appears in the top 3 |
| M3 | status accuracy | over all cases: reported status equals expected status |
| M4 | abstention recall / precision | recall = correct abstentions / cases expecting `insufficient_evidence`; precision = correct abstentions / all abstentions; false abstentions are those on `diagnosed` or `healthy` cases |
| M5 | false-alarm rate | cases expecting `healthy` where the analyzer reports `diagnosed` |
| M6 | unsupported claims | hypotheses with confidence `medium` or `high` whose cause is **not** in `injected` ∪ `downstream_ok` (any case); in `healthy`/`insufficient_evidence` cases any `medium`/`high` hypothesis counts |
| M7 | uncited hypotheses | hypotheses with no evidence reference that resolves to a real finding or raw fact. **Must be 0** |
| M8 | certainty-language violations | outputs containing words asserting certainty (confirmed, definitely, proven, "root cause is", ...). **Must be 0** |

### Comparison baseline (to avoid grading against nothing)

`naive_severity`: map each finding to its problem area, rank by finding severity, report `diagnosed` if any
finding is above `ok`, else `healthy`. It never abstains. It uses exactly the same inputs. The comparison tells
us what the ranking, causal-demotion and abstention logic adds over simply restating the worst finding.

## Decision rule for the optional Ollama backend (fixed in advance)

An LLM backend is justified **only if all** hold:

1. there is measurable headroom: the deterministic analyzer misses or wrongly abstains on a meaningful share of
   held-out cases (or on an input type it cannot read, such as free-text logs);
2. the LLM can be benchmarked here under the same metrics with a stated model name, version, temperature and
   seed, on the same frozen cases;
3. its output validates against a strict schema and does not raise M6/M7/M8 above the deterministic baseline.

If (1) fails there is nothing to improve; if (2) fails, no improvement can honestly be claimed.

## Known limitations of this evaluation (stated up front)

* Cases are **synthetic and written by the same author as the rules**. Scores measure internal consistency and
  regression safety, **not accuracy on real incidents**. Real-world accuracy is unknown.
* n is small (31 cases). Intervals are wide; no significance claims are made.
* Diagnostics thresholds are shared between data and rules; a threshold change moves both.
* No LLM comparison is run unless the decision rule above is met.
