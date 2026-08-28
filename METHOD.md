# Proving that a missing reduction matters

A note on the method behind `mldsa-reduction-audit`, its guarantees, and its
limits. Written for implementers and certification labs.

## The problem

ML-DSA signing (FIPS 204, Algorithm 2) rejects candidate signatures whose
intermediate values fall outside fixed bounds. Those values must be brought
into canonical form before the comparison. Reference implementations do this;
the step is easy to lose in a refactor, and nothing downstream complains —
signatures still verify, known-answer tests still pass.

The general question "is this implementation correct?" is not decidable in
any practical sense. The narrow question "is this particular reduction
load-bearing at this particular site?" is.

## The method

1. Parse the target function into an AST and extract the call sequence in
   source order.
2. For each bounds check, determine whether a reduction stands between it and
   the most recent arithmetic operation.
3. Where none does, hand the site to an SMT solver with the value range
   guaranteed at that point, and ask whether any value in that range makes
   the raw check and the reduced check disagree.
4. Report each site with its verdict, and each flagged site with the witness
   value the solver returned.

Step 3 is what separates this from testing. A test that passes tells you about
the inputs you tried. A solver answering "no such value exists" tells you the
reduction is redundant there — for every value, not for the ones you sampled.
When it answers "here is one", the finding is not a heuristic guess: it comes
with a number that demonstrates the divergence.

## What a certificate does and does not establish

A witness value proves that the raw and reduced comparisons diverge. It does
not establish exploitability, and we do not infer it. In the wolfSSL case the
divergence is one-sided — an unreduced value can only reject a valid candidate,
producing an extra signing loop iteration. That is a correctness and code-quality
divergence from the reference implementations, not a security defect.

## What zero findings means

Three of four audited codebases produced no findings. That is evidence about
false positives, not a clean bill of health. It means: no site of this class,
in the function audited, at that revision. OpenSSL's zero has a structural
explanation — its reduction is fused unconditionally into the arithmetic
primitive, so the class cannot occur there — which is a stronger statement
than the tool alone could make, and we reached it by reading the code.

## Determinism

The pipeline contains no agents and no language models. Parsing, solving and
report generation are deterministic; re-running against the same revision
yields byte-identical output, and reports carry the SHA-256 and version tag of
the file audited. For a reviewing party this matters more than any feature:
a result you cannot reproduce is not evidence.

## Limits

The limits in the README are part of the method, not a disclaimer: one defect
class, one function per run, one parameter set, explicit reduction calls only,
no assembly, last arithmetic step only, names pinned to a library's naming.
The tool fails loudly on a renamed release rather than reporting silence as
safety.

## Related work

Kwon et al. (eprint 2026/1032) analyse reduction placement in ML-DSA and
describe the same defect class; to our knowledge no tool accompanies it.
Crucible (Symbolic Software) and crypto-condor (Quarkslab) search for defects
by exercising inputs, which is complementary: they cover classes we do not,
and by construction do not cover this one.

## Status

The fix for all three sites found in wolfSSL is public:
https://github.com/wolfssl/wolfssl/pull/11113 — reviewer assigned, under
review at the time of writing. We make no claim about its acceptance.

Contact: q2quantum.app@gmail.com
