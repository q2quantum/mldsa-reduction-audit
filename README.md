# mldsa-reduction-audit

A static auditor that checks one thing in ML-DSA (FIPS 204) signing code:
whether a required modular reduction is missing before a bounds check —
and proves, rather than guesses, whether that reduction is load-bearing.

## What it checks

In ML-DSA signing, intermediate values are reduced into a canonical range
before they are compared against rejection-sampling bounds. If the reduction
is absent, the comparison runs on a raw value. Standard functional tests do
not catch this: signatures still verify, test vectors still pass.

## Why a proof instead of test inputs

Fuzzing and test vectors sample the input space. This tool asks a solver
(Z3) a different question about the full value range at once:

> Does there exist any value in the guaranteed range for which the check
> on the raw value and the check on the reduced value disagree?

"Yes" means the reduction is load-bearing, and the solver returns a concrete
witness value. "No" means the reduction is provably redundant at that site,
and the site is not flagged. Every finding ships with its certificate.

The pipeline is fully deterministic — no agents, no language models. Re-running
against the same source revision produces byte-identical output.

## Results

Four independent codebases audited:

| Codebase | Result |
|---|---|
| wolfSSL 5.9.x | 2 sites where an arithmetic result reaches a bounds check with no intervening reduction, both with certificates |
| OpenSSL 3.5 | 0 — reduction is fused into the arithmetic primitive; the class is structurally excluded |
| liboqs / mldsa-native | 0 — reduction present and correct |
| TQ42 Cryptography | 0 — all audited sites correct |

A third site of the same nature was found while preparing the fix. All three
are addressed in a public pull request to wolfSSL:
**https://github.com/wolfssl/wolfssl/pull/11113**

**These findings are not security defects, and we do not present them as such.**
The asymmetry is one-sided: an unreduced value can only reject a valid
candidate — costing an extra signing loop iteration — never accept an invalid
one. What we report is a divergence from three reference implementations
(pq-crystals, PQClean, mldsa-native), all of which reduce at these points.

## Output

Each run produces a JSON and a Markdown report listing every bounds-check
site in the target function, the verdict for each, the witness value for
flagged sites, and the SHA-256 and version tag of the audited file.

## Scope and limitations

We state these ourselves, because a checker that hides its blind spots is
worse than no checker:

- **One defect class.** This is not a general correctness or security audit.
- **One function per run.** No whole-file or whole-project scanning.
- **ML-DSA-44 parameters only.** Thresholds are entered from FIPS 204 by hand.
- **Reduction must be an explicit call.** Where it is fused inline into
  arithmetic, the generic path cannot see it; such targets need a
  target-specific bounds model.
- **No assembly.** If the real computation dispatches into a `.S` file, the
  target is out of scope — not "clean".
- **Only the last arithmetic step before a check is tracked.** Earlier
  reductions in a longer chain are not considered. This tool does not check
  every reduction, and we do not claim that it does.
- **Function names are pinned to a library's naming.** On a renamed release
  the run fails loudly rather than reporting a false "no findings".
- **Zero findings means zero findings of this class, at the sites audited.**
- **Check-site labels are assigned by order of appearance by default**, not
  by matching what each check verifies — on a target whose code differs from
  the reference layout in the number or order of bounds checks, labels can
  be silently wrong. Override with `--site-order` if in doubt.

## Availability

The auditor runs locally: audited source is never copied to us — you point it
at your own checkout, and your code never leaves your machine. The tool is
available on request while we finish preparing it for public release.

Reading the method in detail: [METHOD.md](METHOD.md).

## Who we are

Q² quantum ecosystem — an independent team in Tbilisi, Georgia, mapping
the quantum technology sector and building products on top of that map. This
auditor is the first of them.

Contact: q2quantum.app@gmail.com

## License

The text in this repository (this README and METHOD.md) is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Code, when it is
added here, will be released under the Apache License 2.0.
