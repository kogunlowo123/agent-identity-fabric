Your AI agents probably authenticate the way a 2010 cron job did: a shared secret in an environment variable.

That works until an agent is prompt-injected, leaks its key into a log, or quietly hands its access to another agent. Then three questions matter: which agent did this, on whose behalf, and can we stop it now?

Why it matters: auditors already expect attributable, revocable access for people. Agents act faster, so the bar is the same with less tolerance for delay.

The flow I built:
Workload token → Attestation → Agent identity → Short-lived credential → Delegation → Authorization → Audit → Revocation

How it works:
1. Every agent is registered with a mandate: mission, owners, allowed scopes, risk tier, data-classification ceiling.
2. No static secrets. The agent proves which Kubernetes workload it runs as; the fabric verifies the token against the cluster JWKS, the bound service account and an image-digest allow list.
3. Credentials are Ed25519 JWTs that live ten minutes.
4. Delegation uses OAuth token exchange (RFC 8693). Scopes are the intersection of both agents, the chain is recorded, depth is capped, and a delegated token can never outlive its parent.
5. Every action goes through a policy decision point. Delegated writes and critical-risk agents return "requires approval", not "allow".
6. Suspension bumps a credential epoch, so every outstanding token for that agent dies at once.
7. Each decision lands in a signed, hash-chained audit trail shipped to WORM storage.

Best practices: fail closed when evidence cannot be written; keep keys out of Terraform state; enforce classification ceilings outside policy.

Tradeoffs: introspection adds a network hop; local verification is faster but tolerates up to fifteen minutes of staleness. Teams choose per resource. Workload attestation also ties you to the platform's identity issuer.

Value: containment is one API call; audits become a query, not a forensic project.

As agent ecosystems span vendors and clouds, identity becomes the control plane everything else hangs on.

Question for architects: should delegated agent authority ever be allowed to cross organizational trust domains without a human in the loop?

Code: github.com/kogunlowo123/agent-identity-fabric

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #ZeroTrust #OAuth #SPIFFE
