# Compliance control mapping

Evidence column names the artifact an auditor can inspect.

| Control objective | HIPAA Security Rule | SOC 2 (TSC 2017) | ISO/IEC 27001:2022 | NIST SP 800-53 r5 | NIST AI RMF 1.0 | 21 CFR Part 11 / GxP | Evidence |
|---|---|---|---|---|---|---|---|
| Unique identity per agent | 164.312(a)(2)(i) | CC6.1 | 5.16 | IA-2, IA-9 | GOVERN 1.4 | 11.10(d), 11.300(a) | `agents` table, `GET /v1/agents` |
| Identity proofing before credentials | 164.312(d) | CC6.1 | 5.17 | IA-3, IA-9 | MAP 3.5 | 11.300 | Attestation audit events |
| Least privilege | 164.308(a)(4) | CC6.3 | 5.15, 8.2 | AC-6 | MANAGE 2.4 | 11.10(g) | Scopes, policy set, `/v1/authorize` decisions |
| Delegation is bounded and attributable | 164.308(a)(3) | CC6.2 | 5.18 | AC-6(9), AU-10 | GOVERN 2.1 | 11.10(g) | `act` chain in tokens and audit |
| Timely access removal | 164.308(a)(3)(ii)(C) | CC6.2 | 5.18 | AC-2(3), AC-2(8) | MANAGE 4.1 | 11.10(d) | Suspension/revocation events, epoch |
| Audit trail integrity | 164.312(b) | CC7.2 | 8.15 | AU-9, AU-10 | MEASURE 2.8 | 11.10(e) | Signed chains in WORM storage, `verify_chain` |
| Credential and key protection | 164.312(a)(2)(iv) | CC6.1 | 8.24 | SC-12, SC-13 | MANAGE 2.3 | 11.300(b) | KMS, secret manager, rotation records |
| Change control of authorization policy | 164.308(a)(8) | CC8.1 | 8.32 | CM-3 | GOVERN 1.4 | 11.10(k) | Git history, CODEOWNERS, policy digest |
| Monitoring and response | 164.308(a)(6) | CC7.3 | 5.24 | IR-4, SI-4 | MANAGE 4.1 | — | Alert rules, incident runbook |
| Availability | 164.308(a)(7) | A1.2 | 8.14 | CP-10 | — | — | HA database, PDB, DR runbook |

GxP: the fabric supports computerized system validation by producing
attributable, time-stamped, tamper-evident records of who (which agent, on
whose behalf) did what. Validation (IQ/OQ/PQ) of a deployment uses the CI run
for the deployed tag as OQ evidence for the functional requirements listed in
`docs/architecture/agent-specification.md`.
