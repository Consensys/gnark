# Linea GKR Protocol Specification

This document serves as a specification for the Linea GKR protocol, as recommended in the audit report and tracked in [issue #1280](https://github.com/Consensys/gnark/issues/1280). This specification is based solely on the information provided in the issue description. Where the issue calls for clarification or correction, but does not provide the actual content, a placeholder is included.

## 1. Definition of $V_O(\rho)$

> **Placeholder:** The definition of $V_O(\rho)$ is required. The issue notes that this was not defined in Figure 15 (p. 15) of the reference paper [BSB22].

## 2. Claim Register `claims` Type Definition

> **Placeholder:** The type definition for the claim register `claims` should be made more direct, rather than only being defined in a comment as in Figure 15 (p. 15) of [BSB22].

## 3. Batch Assignment for Input and Output Gates

> **Placeholder:** The batch assignment should be defined for the specific cases of input and output gates, as noted in Definition B.2 (p. 14) of [BSB22].

## 4. Call to `miniProtocol2`

> **Placeholder:** The call to `miniProtocol2` should be on $(v, \text{claim}')$ as per Figure 15 (p. 15) of [BSB22].

## 5. Summation Domain for $B(v)(x)$

> **Placeholder:** In Remark B.3 (p. 14) of [BSB22], the defining equation for $B(v)(x)$ over $K^n$ should have the summation over the hypercube $\{0,1\}^n$.

## 6. Extension Field Tower

> **Placeholder:** The specification should contain more information about the extension field tower, as this is a necessary addition to the protocol per the audit report.

---

**Note:** This specification is a work in progress and will be updated as more precise information becomes available. All content above is strictly based on the audit issue description and does not include any invented or assumed details. 
