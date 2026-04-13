# Are u Ai Addicted - Writeup
**Challenge Name**: `Are u AI addicted?`
**Platform**: `CodeVinci CTF`
**Category**: `Crypto`

## Goal (What was the task?)
We had to reverse-engineer a remote matrix-based black box. The service exponentiated a 4×4 companion matrix with unknown coefficients over F𝑝 (p=2⁶¹−1) and, after providing four queries, expected us to return the base coefficients so it would reveal the flag (CodeVinci{...}).

## Key Clues (What mattered?)

- Prompt mentioned massive matrix exponentiations and Mersenne-prime modulus, hinting at modular linear recurrences.
- The server let us feed four vectors and returned their matrix images for four attempts, so it was clearly returning columns of Mᴱ for different basis inputs.
- AGENT_NOTICE specifically recommended using Z3 bounded model checking to unroll the matrix—implying companion/recurrent structure.
- The modulus and exponent (E=2⁵²¹−1) and request for secrets (c₀…c₃) matched the coefficients of a companion matrix.

## Plan (Your first logical approach)

- Query the service with the canonical basis to obtain all four columns of Mᴱ, giving us one full matrix per session.
- Compute the characteristic polynomial of that matrix modulo p; its roots are E-th powers of the companion matrix eigenvalues.
- Recover the eigenvalues by taking modular E-th roots via modular inverses in both Fₚ and the quadratic extension Fₚ², then reconstruct c₀…c₃ as elementary symmetric sums.

## Steps (Clean execution)

1. Connected to addicted.codevinci.it:9978 and fed (1,0,0,0), (0,1,0,0), (0,0,1,0), (0,0,0,1) to collect the output columns -> observed four 4-element vectors corresponding to Mᴱ acting on basis vectors.
2. Built the 4×4 matrix whose columns were those outputs, computed its characteristic polynomial using Sympy, and reduced coefficients modulo p to avoid overflow errors.
3. Factored the polynomial mod p; two roots lived in Fₚ and the remaining quadratic factor had a non-residue discriminant, so we promoted to Fₚ² using the quadratic extension.
4. Raised each root to the power E⁻¹ mod (p−1) or mod (p²−1) accordingly, yielding the companion matrix eigenvalues λᵢ.
5. Computed c₀…c₃ as alternating sums/products of the λᵢ, matching the companion matrix definition, then re-verified by re-exponentiating the matrix to confirm the recovered matrix produced the same outputs.
6. Submitted the four coefficients; the server responded with the flag.

## Solution Summary (What worked and why?)
Because the service exponentiates a companion matrix, its output columns are deterministic E-th powers of its eigenvalues. Factoring the characteristic polynomial gives us those powers, and taking modular E-th roots (in Fₚ and Fₚ²) recovers the eigenvalues. By writing the matrix coefficients as symmetric sums of the eigenvalues we reconstruct the original matrix and feed the secrets back, which triggers the flag reveal.

## Flag
`CodeVinci{g0t_sh3ll_n0_p1zz4_v1t4_tr1st3}`

## Lessons Learned (make it reusable)

- Companion matrices and modular recurrences can be reversed through characteristic polynomials and root extraction.
- When exponents land in a quadratic extension (non-square discriminant), implement arithmetic in Fₚ² right away instead of forcing a square root in Fₚ.
- Always verify recovered coefficients by re-running the powerful transformation to ensure the observed oracle outputs match the reconstructed matrix.
- Next time start by collecting canonical basis outputs so I have a full matrix to analyze before guessing any recurrence.

## Personal Cheat Sheet (optional, but very useful)

- Sympy `Matrix.charpoly()` → derive companion polynomial from oracle matrix.
- Modular E-th root → raise roots to `pow(E, -1, modulus)` in Fₚ or Fₚ².
- Companion matrix form → coefficients are alternating sums/products of eigenvalues; submit c₀=c₁=… accordingly.
