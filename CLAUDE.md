# vc-operator

## Overview
A Kubernetes operator that manages Verifiable Credentials (VCs) for services in FIWARE-ecosystem deployments. It obtains credentials via OID4VCI (OpenID for Verifiable Credential Issuance), stores them as Kubernetes Secrets, and automatically renews them before expiry.

## Tech Stack
- Language: Go 1.22+
- Build: Make (kubebuilder-generated Makefile)
- Framework: Kubebuilder 4.x / controller-runtime
- Test: Go testing + envtest (controller-runtime test framework), testcontainers-go for integration tests
- Container: Docker multi-stage build
- Deployment: Helm 3 chart + Kustomize manifests (kubebuilder default)

## Project Structure
```
├── api/v1alpha1/          # CRD Go types (CredentialIssuer, VerifiableCredentialRequest)
├── cmd/                   # Operator entrypoint (main.go)
├── internal/
│   ├── controller/        # Reconciler implementations
│   ├── oid4vci/           # OID4VCI client library (metadata, token, credential)
│   └── credential/        # Credential parsing, expiry, storage helpers
├── config/
│   ├── crd/               # Generated CRD manifests
│   ├── rbac/              # RBAC manifests
│   ├── manager/           # Deployment manifests
│   └── samples/           # Example CRs
├── charts/vc-operator/    # Helm chart
├── test/e2e/              # Integration tests with Keycloak
├── Dockerfile
├── Makefile
└── PROJECT                # Kubebuilder project metadata
```

## Build & Test
```bash
make generate          # Run code generators (deepcopy, CRD manifests)
make manifests         # Generate CRD/RBAC manifests
make build             # Build the operator binary
make test              # Run unit tests with envtest
make docker-build      # Build container image
make docker-push       # Push container image
make install           # Install CRDs into cluster
make deploy            # Deploy operator to cluster
make helm-install      # Install via Helm chart
```

## Key Conventions
- Kubebuilder markers for CRD generation (`+kubebuilder:...`)
- controller-runtime reconciler pattern (Reconcile method returns ctrl.Result)
- Status conditions follow Kubernetes API conventions (metav1.Condition)
- All durations in CRD specs use Kubernetes duration format (e.g., `5m`, `1h`)
- Secrets follow label convention: `app.kubernetes.io/managed-by: vc-operator`

## Important Files
- `api/v1alpha1/types.go` — CRD type definitions
- `internal/controller/credentialissuer_controller.go` — CredentialIssuer reconciler
- `internal/controller/vcrequest_controller.go` — VerifiableCredentialRequest reconciler
- `internal/oid4vci/client.go` — OID4VCI protocol client
- `internal/oid4vci/metadata.go` — Issuer metadata discovery
- `internal/oid4vci/token.go` — Token endpoint interactions
- `internal/credential/jwt.go` — JWT VC parsing and expiry extraction
- `config/samples/` — Example CR manifests for testing
- `charts/vc-operator/values.yaml` — Helm chart default values
