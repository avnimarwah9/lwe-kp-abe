# An LWE-Based Attribute-Based Encryption Framework: Post-Quantum Fine-Grained Access Control for Institutional Systems

**M.Sc. Thesis | Applied Mathematics | South Asian University, New Delhi | May 2026**

Author: Avni Marwah
Supervisor: Prof. Jagdish Chand Bansal
Affiliation: Department of Mathematics, Faculty of Mathematical Sciences, South Asian University

---

## Overview

This thesis develops a complete, mathematically rigorous treatment of lattice-based Key-Policy Attribute-Based Encryption (KP-ABE), from classical public-key foundations through to a verified Python simulation of a real institutional access control system.

The central construction follows the BGG+14 scheme (Boneh, Gentry, Gorbunov, Halevi, Nikolaenko, Segev, Vaikuntanathan, and Vinayagamurthy, EUROCRYPT 2014), the first KP-ABE scheme supporting arbitrary Boolean circuit access policies under standard Learning With Errors (LWE) assumptions.

The motivation is concrete: RSA and pairing-based ABE schemes are broken by Shor's algorithm on a sufficiently large quantum computer. Recent resource estimates place 2048-bit RSA factorization within reach of under one million physical qubits. Systems relying on these assumptions are already vulnerable to harvest-now, decrypt-later attacks. This thesis builds the LWE-based alternative from the ground up.

---

## Contributions

**1. Hand-computed numerical example over Z17**

A complete, step-by-step execution of Setup, KeyGen, Encryption, and Decryption for the BGG+14 scheme over the integers modulo 17. Every matrix operation, gadget decomposition, and decryption check is worked out by hand and verified. This serves as a self-contained correctness check of the construction at small parameters.

**2. Python simulation across 20 users and 680 message bits**

A full implementation of the BGG+14 KP-ABE scheme in Python, applied to a university document access control system with:
- 20 users with distinct institutional attribute sets
- 10 attributes (e.g., faculty status, department, clearance level)
- A depth-4 Boolean circuit access policy
- 680 message bits tested end-to-end

Authorised users recover the plaintext exactly. Unauthorised users, including near-miss cases satisfying all but one policy condition, receive cryptographically uncorrelated output. All 680 bits verified correct.

---

## Thesis Structure

| Chapter | Topic |
|--------|-------|
| 1 | Introduction and motivation |
| 2 | RSA: number-theoretic foundations, primality testing, factorization algorithms |
| 3 | Shor's algorithm and quantum threat to RSA |
| 4 | Post-quantum primitives: McEliece (code-based) and LWE/MLWE/RLWE (lattice-based) |
| 5 | Kyber (NIST-standardized KEM from MLWE) |
| 6 | Key-Policy Attribute-Based Encryption: BGG+14 construction, gadget matrices, homomorphic evaluation, selective security proof |
| 7 | University access control application, numerical example, Python simulation |

---

## Key Concepts Covered

- Learning With Errors (LWE), Ring-LWE, Module-LWE
- Gadget matrix G and binary decomposition operator G-inverse
- Tensor product attribute encodings
- Homomorphic evaluation of Boolean circuits and their transposes
- Selective security under LWE
- McEliece cryptosystem over binary Goppa codes
- Kyber KEM (CRYSTALS-Kyber, FIPS 203)

---

## Files

| File | Description |
|------|-------------|
| `thesis.pdf` | Full thesis document (156 pages) |
| `simulation/bgg14_kpabe.py` | Python simulation of the BGG+14 KP-ABE scheme |

---

## Simulation

`simulation/bgg14_kpabe.py` is a standalone Python implementation of the BGG+14 KP-ABE scheme applied to a university document access control scenario.

**Parameters**

| Parameter | Value |
|-----------|-------|
| LWE dimension n | 4 |
| Modulus q | 97 (prime) |
| Gadget bit-width k | 7 |
| Attribute universe | 10 attributes |
| Users | 20 |
| Message | 85 characters / 680 bits |

**Access policy**

f(x) = ( (Professor AND MathDept) OR (PhD AND ResearchGroup) )
        AND ( (LibraryAccess OR FinanceClearance) AND ResearchSupervisor )

Circuit depth: 4.

**Requirements**

numpy

**Run**

pip install numpy
python bgg14_kpabe.py

---

## Citation

If you find this work useful, please cite as:

Marwah, A. (2026). An LWE-Based Attribute-Based Encryption Framework: Post-Quantum Fine-Grained
Access Control for Institutional Systems. M.Sc. Thesis, South Asian University, New Delhi.

This thesis is also available as a public preprint on ResearchGate.

---

## Contact

Avni Marwah
Research Intern, SAG Lab, DRDO
M.Sc. Applied Mathematics, South Asian University (2026)
