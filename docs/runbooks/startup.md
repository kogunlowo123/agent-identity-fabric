# Runbook: first deployment and startup

## Prerequisites

- Kubernetes ≥ 1.27 with an OIDC issuer for service-account tokens (EKS, AKS
  and GKE enable this by default), External Secrets Operator, and a
  `ClusterSecretStore` named `platform-secrets` for the cloud secret manager.
- Enterprise IdP app registration exposing roles `agent-registrar`,
  `agent-security-officer`, `agent-auditor`.

## 1. Provision cloud resources

```bash
cd deployments/terraform/aws        # or azure / gcp
terraform init                      # configure an encrypted remote backend first
terraform apply -var-file=<environment>.tfvars
```

Record the outputs: workload-identity binding, secret names, KMS key, audit
bucket.

## 2. Create signing and audit keys

```bash
uv run python -m identity_fabric.keygen 2026-10 \
  2> signing-2026-10.jwk.json \
  | aws secretsmanager create-secret --name agent-identity-fabric-signing-key-2026-10 \
      --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin

uv run python -m identity_fabric.keygen 2026-10 2>/dev/null \
  | aws secretsmanager create-secret --name agent-identity-fabric-audit-key-2026-10 \
      --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin
```

Azure: `az keyvault secret set --vault-name <vault> --name ... --file /dev/stdin`.
GCP: `gcloud secrets create ... --data-file=-`.

## 3. Namespace and secret sync

```bash
kubectl apply -k deployments/kubernetes
kubectl -n agent-identity get externalsecret   # all READY=True
```

## 4. Install the chart

Create `<environment>.yaml` with every value marked REQUIRED in
`values.yaml`, plus the workload-identity annotation from Terraform:

```bash
helm upgrade --install fabric oci://ghcr.io/kogunlowo123/charts/agent-identity-fabric \
  --version 0.1.0 -n agent-identity -f <environment>.yaml --wait
```

## 5. Verify

```bash
kubectl -n agent-identity rollout status statefulset/fabric-agent-identity-fabric
kubectl -n agent-identity port-forward svc/fabric-agent-identity-fabric 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/.well-known/jwks.json | jq '.keys[].kid'
```

Expected: `{"status":"ready"}` and the active kid listed. Prometheus target
`agent-identity-fabric` is up; Grafana dashboard
`configs/grafana/agent-identity-fabric.json` shows traffic.
