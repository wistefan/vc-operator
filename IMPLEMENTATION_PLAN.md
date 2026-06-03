# Implementation Plan: Create a VC Operator

## Overview
Build a Kubernetes operator in Go (using Kubebuilder) that obtains Verifiable Credentials via the OID4VCI protocol, stores them securely, and automatically renews them before expiry. The operator introduces two Custom Resource Definitions — `CredentialIssuer` (configures an OID4VCI issuer such as Keycloak) and `VerifiableCredentialRequest` (declares a credential a service needs). The first supported issuer is Keycloak.

Credential storage is implemented behind a `CredentialStore` interface, with Kubernetes Secrets as the default backend. This abstraction allows adding alternative storage backends (e.g., HashiCorp Vault, AWS Secrets Manager) in the future without modifying the controllers.

## Steps

### Step 1: Project Scaffolding and Build Setup

Initialize the Go module and scaffold the Kubernetes operator project using Kubebuilder.

**What to do:**
- Run `kubebuilder init --domain vc-operator.io --repo github.com/wistefan/vc-operator` to scaffold the project.
- Run `kubebuilder create api --group vc --version v1alpha1 --kind CredentialIssuer` and `kubebuilder create api --group vc --version v1alpha1 --kind VerifiableCredentialRequest` to create the API scaffolds and controller stubs.
- Configure the `Makefile` and `Dockerfile` (kubebuilder generates these; adjust Go version, image name).
- Add a `.golangci-lint.yml` with sensible linting rules (govet, errcheck, staticcheck, unused).
- Add a `.gitignore` for Go/kubebuilder artifacts.
- Ensure `make build` and `make test` pass with the scaffolded code.

**Files created/modified:**
- `go.mod`, `go.sum`
- `Makefile`, `Dockerfile`
- `PROJECT`
- `cmd/main.go`
- `api/v1alpha1/` (scaffold stubs)
- `internal/controller/` (scaffold stubs)
- `config/` (kubebuilder-generated kustomize manifests)
- `.golangci-lint.yml`, `.gitignore`

**Acceptance criteria:**
- `make generate && make manifests && make build && make test` all pass.
- Project structure matches kubebuilder conventions.

---

### Step 2: CRD Type Definitions

Define the full API types for both Custom Resources with proper validation markers, status conditions, and GoDoc documentation.

**What to do:**

Define `CredentialIssuer` CRD:
```go
// CredentialIssuerSpec configures an OID4VCI credential issuer.
type CredentialIssuerSpec struct {
    // IssuerURL is the base URL of the OID4VCI credential issuer.
    // The operator discovers metadata at {IssuerURL}/.well-known/openid-credential-issuer
    IssuerURL string `json:"issuerURL"`

    // IssuerType identifies the issuer implementation (e.g., "keycloak").
    // Defaults to "generic" if not specified.
    IssuerType string `json:"issuerType,omitempty"`

    // AuthSecretRef references a Kubernetes Secret containing authentication
    // credentials for the token endpoint (e.g., client_id, client_secret).
    AuthSecretRef SecretReference `json:"authSecretRef"`

    // TokenURL optionally overrides the token endpoint discovered from metadata.
    TokenURL string `json:"tokenURL,omitempty"`
}
```

Define `VerifiableCredentialRequest` CRD:
```go
// VerifiableCredentialRequestSpec defines the desired credential.
type VerifiableCredentialRequestSpec struct {
    // IssuerRef references a CredentialIssuer in the same namespace.
    IssuerRef LocalObjectReference `json:"issuerRef"`

    // CredentialType is the type identifier for the credential to request
    // (as advertised in the issuer's credential_configurations_supported).
    CredentialType string `json:"credentialType"`

    // Format specifies the credential format (e.g., "jwt_vc_json", "ldp_vc").
    // Defaults to "jwt_vc_json".
    Format string `json:"format,omitempty"`

    // StorageType selects the credential storage backend.
    // Supported values: "kubernetes" (default). Future: "vault".
    // +kubebuilder:validation:Enum=kubernetes
    // +kubebuilder:default=kubernetes
    StorageType string `json:"storageType,omitempty"`

    // TargetSecretRef specifies the target reference in the storage backend
    // where the obtained credential will be stored (e.g., a Kubernetes Secret name).
    TargetSecretRef TargetSecretReference `json:"targetSecretRef"`

    // RenewBefore specifies how long before credential expiry the operator
    // should attempt renewal. Defaults to "5m".
    RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`

    // AdditionalClaims allows specifying extra claims to include in the
    // credential request (issuer-specific).
    AdditionalClaims map[string]string `json:"additionalClaims,omitempty"`
}
```

Define status types with standard Kubernetes conditions (`Ready`, `CredentialIssued`, `RenewalScheduled`, `Error`).

- Add kubebuilder validation markers (`+kubebuilder:validation:Required`, `+kubebuilder:validation:Enum`, `+kubebuilder:validation:Pattern`, etc.).
- Add printer columns for `kubectl get` output.
- Implement `DeepCopyObject` via `make generate`.
- Run `make manifests` to generate CRD YAML.
- Write sample CRs in `config/samples/`.

**Files created/modified:**
- `api/v1alpha1/credentialissuer_types.go`
- `api/v1alpha1/verifiablecredentialrequest_types.go`
- `api/v1alpha1/common_types.go` (shared types like SecretReference, conditions)
- `api/v1alpha1/zz_generated.deepcopy.go` (generated)
- `config/crd/bases/` (generated CRD manifests)
- `config/samples/vc_v1alpha1_credentialissuer.yaml`
- `config/samples/vc_v1alpha1_verifiablecredentialrequest.yaml`

**Acceptance criteria:**
- `make generate && make manifests` produce valid CRD YAML.
- Sample CRs pass `kubectl apply --dry-run=client` validation.
- All types have GoDoc comments.
- Kubebuilder validation markers are present on all required fields.

---

### Step 3: OID4VCI Client Library

Implement the OID4VCI protocol client as a standalone internal package that handles metadata discovery, token acquisition, and credential issuance requests.

**What to do:**

1. **Metadata discovery** (`internal/oid4vci/metadata.go`):
   - Fetch `{issuerURL}/.well-known/openid-credential-issuer` and parse the JSON response.
   - Extract: `credential_endpoint`, `token_endpoint`, `credential_configurations_supported`.
   - Define Go structs for the metadata response.

2. **Token acquisition** (`internal/oid4vci/token.go`):
   - Implement `client_credentials` grant (primary flow for service-to-service).
   - Implement `pre-authorized_code` grant (for pre-authorized code flow).
   - Parse token response: `access_token`, `c_nonce`, `c_nonce_expires_in`, `token_type`.

3. **Credential request** (`internal/oid4vci/credential.go`):
   - Build credential request with `credential_configuration_id`, `format`, and `proof` (JWT proof-of-possession containing `c_nonce`).
   - Generate proof-of-possession JWT signed with operator's key.
   - Parse credential response: extract the issued credential.

4. **Key management** (`internal/oid4vci/keys.go`):
   - Generate and manage an ephemeral ECDSA P-256 key pair for proof-of-possession JWTs.
   - Optionally load key from a Kubernetes Secret for persistence across restarts.

5. **Client interface** (`internal/oid4vci/client.go`):
   - Define a high-level `Client` interface:
     ```go
     type Client interface {
         DiscoverMetadata(ctx context.Context, issuerURL string) (*IssuerMetadata, error)
         ObtainAccessToken(ctx context.Context, tokenURL string, auth TokenAuth) (*TokenResponse, error)
         RequestCredential(ctx context.Context, credentialURL string, accessToken string, request CredentialRequest) (*CredentialResponse, error)
     }
     ```
   - Implement with configurable `http.Client` for testability.

**Files created/modified:**
- `internal/oid4vci/metadata.go` + `metadata_test.go`
- `internal/oid4vci/token.go` + `token_test.go`
- `internal/oid4vci/credential.go` + `credential_test.go`
- `internal/oid4vci/keys.go` + `keys_test.go`
- `internal/oid4vci/client.go` + `client_test.go`
- `internal/oid4vci/types.go` (shared request/response types)

**Acceptance criteria:**
- All functions have unit tests using `httptest.Server` to mock OID4VCI endpoints.
- Parameterized tests cover multiple credential formats and error cases.
- The client handles HTTP errors, invalid JSON, and timeouts gracefully.
- All public types and functions have GoDoc comments.
- No hardcoded URLs or magic constants — all configurable or defined as named constants.

---

### Step 4: Credential Parsing and Expiry Extraction

Implement utilities for parsing Verifiable Credentials (JWT format) and extracting expiry information to support lifecycle management.

**What to do:**

1. **JWT VC parsing** (`internal/credential/jwt.go`):
   - Parse JWT VCs (compact serialization) without full signature verification (the operator trusts the issuer; verification is the holder/verifier's responsibility).
   - Extract standard claims: `exp` (expiry), `iat` (issued-at), `iss` (issuer), `sub` (subject).
   - Extract VC-specific claims from the `vc` payload claim.

2. **Expiry calculation** (`internal/credential/expiry.go`):
   - Given a credential and a `renewBefore` duration, compute when renewal should be triggered.
   - Handle credentials without explicit expiry (treat as non-expiring or use a configurable default TTL).
   - Define constants for default renewal buffer and maximum credential lifetime.

3. **Credential store interface** (`internal/credentialstore/store.go`):
   - Define a `CredentialStore` interface that abstracts storage operations:
     ```go
     // CredentialStore abstracts the storage backend for obtained credentials.
     // The default implementation uses Kubernetes Secrets. Alternative backends
     // (e.g., HashiCorp Vault, AWS Secrets Manager) can be added by implementing
     // this interface.
     type CredentialStore interface {
         // Store persists a credential to the storage backend.
         Store(ctx context.Context, ref TargetRef, data *CredentialData) error
         // Retrieve loads a previously stored credential.
         Retrieve(ctx context.Context, ref TargetRef) (*CredentialData, error)
         // Delete removes a stored credential.
         Delete(ctx context.Context, ref TargetRef) error
     }
     ```
   - Define `CredentialData` struct containing credential bytes, format, issuer, expiry timestamp, and previous credential (for rotation buffer).
   - Define `TargetRef` struct containing namespace, name, and optional owner reference info.

4. **Kubernetes Secrets backend** (`internal/credentialstore/kubernetes/secrets.go`):
   - Implement `CredentialStore` using Kubernetes Secrets as the storage backend.
   - Build Kubernetes Secret data from a credential response.
   - Define the Secret data schema: keys for credential, format, issuer, expiry timestamp.
   - Add labels/annotations for operator management (`app.kubernetes.io/managed-by: vc-operator`).
   - Set owner references so the Secret is garbage-collected when the CR is deleted.

**Files created/modified:**
- `internal/credential/jwt.go` + `jwt_test.go`
- `internal/credential/expiry.go` + `expiry_test.go`
- `internal/credential/constants.go` (named constants)
- `internal/credentialstore/store.go` (interface definition)
- `internal/credentialstore/kubernetes/secrets.go` + `secrets_test.go`

**Acceptance criteria:**
- JWT parsing correctly extracts claims from real-world-format JWT VCs (test with crafted JWTs).
- Expiry calculation handles edge cases: no expiry, already expired, expiry in the past.
- Parameterized tests cover multiple JWT structures and claim combinations.
- `CredentialStore` interface is well-documented and implementation-agnostic.
- Kubernetes Secrets backend correctly produces valid Secret objects with correct labels/annotations.
- Backend is tested with a mock Kubernetes client.

---

### Step 5: CredentialIssuer Controller

Implement the reconciler for the `CredentialIssuer` custom resource. This controller validates issuer connectivity and caches metadata.

**What to do:**

1. **Reconciler** (`internal/controller/credentialissuer_controller.go`):
   - On create/update: fetch OID4VCI metadata from the issuer URL.
   - Validate that the referenced auth Secret exists and has required keys (`client_id`, `client_secret` or `pre_authorized_code`).
   - Store discovered metadata (credential endpoint, token endpoint, supported types) in the CR status.
   - Set status conditions: `Ready` (metadata fetched successfully), `Error` (connectivity or auth issues).
   - Requeue periodically (e.g., every 30 minutes) to refresh metadata.

2. **RBAC markers**:
   - Add kubebuilder RBAC markers for Secrets (get, list, watch) and CredentialIssuer (get, list, watch, update, patch, status).

3. **Event recording**:
   - Record Kubernetes events for successful metadata discovery, connectivity errors, and auth Secret issues.

**Files created/modified:**
- `internal/controller/credentialissuer_controller.go` (full implementation)
- `internal/controller/credentialissuer_controller_test.go` (envtest-based tests)
- `internal/controller/suite_test.go` (shared test suite setup with envtest)

**Acceptance criteria:**
- Controller sets `Ready=True` when metadata is successfully fetched (test with mock HTTP server).
- Controller sets `Ready=False` with reason when issuer is unreachable or auth secret is missing.
- Status is updated with discovered metadata endpoints.
- Events are recorded for key state transitions.
- Tests use envtest (controller-runtime test framework).

---

### Step 6: VerifiableCredentialRequest Controller and Credential Storage

Implement the main reconciler that obtains credentials via OID4VCI and stores them using the pluggable `CredentialStore` interface.

**What to do:**

1. **Reconciler** (`internal/controller/vcrequest_controller.go`):
   - On create/update:
     a. Look up the referenced `CredentialIssuer` and verify it is `Ready`.
     b. Read auth credentials from the issuer's referenced Secret.
     c. Use the OID4VCI client to obtain an access token.
     d. Request the specified credential type and format.
     e. Parse the returned credential to extract expiry.
     f. Store the credential via the injected `CredentialStore` backend.
     g. Set status conditions: `CredentialIssued`, `Ready`.
     h. Compute next renewal time and requeue accordingly.
   - On delete: optionally clean up the target Secret (configurable via finalizer).

2. **Credential storage** (via `CredentialStore` interface):
   - Use the `CredentialStore` interface (defined in Step 4) to persist credentials to the configured backend.
   - The controller receives a `CredentialStore` implementation via dependency injection (constructor parameter), defaulting to the Kubernetes Secrets backend.
   - This design allows swapping in alternative backends (e.g., HashiCorp Vault) without modifying controller logic.

3. **Error handling**:
   - Implement exponential backoff for transient OID4VCI errors.
   - Set `Error` condition with descriptive message for permanent failures (invalid credential type, auth failure).
   - Distinguish between retriable and non-retriable errors.

4. **RBAC markers**:
   - Secrets (create, get, list, watch, update, patch, delete).
   - CredentialIssuer (get, list, watch).
   - VerifiableCredentialRequest (get, list, watch, update, patch, status).

**Files created/modified:**
- `internal/controller/vcrequest_controller.go`
- `internal/controller/vcrequest_controller_test.go`
- Update `cmd/main.go` to register both controllers with the manager.

**Acceptance criteria:**
- Full happy-path test: CR created → credential obtained → credential stored via `CredentialStore`.
- Error-path tests: issuer not ready, auth secret missing, OID4VCI endpoint returns error.
- Controller is tested with a mock `CredentialStore` to verify storage-agnostic behavior.
- Status conditions accurately reflect the current state.
- Requeue duration matches the expected renewal time.

---

### Step 7: Credential Renewal and Lifecycle Management

Implement automatic credential renewal before expiry and handle edge cases in the credential lifecycle.

**What to do:**

1. **Renewal scheduling** (enhance `internal/controller/vcrequest_controller.go`):
   - After successful credential issuance, calculate `requeueAfter = expiryTime - now - renewBefore`.
   - On requeue, re-execute the full credential acquisition flow.
   - Update the target Secret with the new credential atomically.
   - Record events for successful renewal and renewal failures.

2. **Startup reconciliation**:
   - On operator startup, reconcile all existing `VerifiableCredentialRequest` CRs.
   - Check stored credentials for imminent expiry and trigger immediate renewal if needed.

3. **Credential rotation safety**:
   - Store the previous credential alongside the new one in the `CredentialData` (one-deep rotation buffer) so consuming services have a grace period. The `CredentialStore` backend handles the storage details (e.g., Secret annotation for Kubernetes, versioned secret for Vault).
   - Add a `status.lastRenewalTime` and `status.nextRenewalTime` to the CR status.

4. **Metrics** (optional but recommended):
   - Expose Prometheus metrics: `vc_operator_credentials_issued_total`, `vc_operator_credentials_renewed_total`, `vc_operator_credentials_errors_total`, `vc_operator_credential_expiry_seconds` (gauge).
   - Register metrics with controller-runtime's metrics registry.

**Files created/modified:**
- `internal/controller/vcrequest_controller.go` (enhance renewal logic)
- `internal/controller/vcrequest_controller_test.go` (renewal tests)
- `internal/controller/metrics.go` (Prometheus metrics)
- `api/v1alpha1/verifiablecredentialrequest_types.go` (add renewal status fields)

**Acceptance criteria:**
- A credential nearing expiry is automatically renewed without manual intervention.
- Renewal tests simulate time progression (use fakeclock or injectable time source).
- The previous credential is preserved in an annotation during rotation.
- Prometheus metrics are registered and incremented correctly.

---

### Step 8: Helm Chart and Deployment Manifests

Create a production-ready Helm chart and finalize Kustomize manifests for deploying the operator.

**What to do:**

1. **Helm chart** (`charts/vc-operator/`):
   - `Chart.yaml` with proper metadata (name, version, appVersion, description).
   - `values.yaml` with configurable: image repository/tag, replica count, resource limits, log level, leader election, namespace, service account, RBAC.
   - Templates: Deployment, ServiceAccount, ClusterRole, ClusterRoleBinding, CRDs (optional install), metrics Service.
   - NOTES.txt with post-install instructions.

2. **Kustomize manifests** (update kubebuilder-generated `config/`):
   - Ensure CRD manifests are up to date.
   - Configure resource limits in manager deployment.
   - Add network policy (optional).

3. **Container image**:
   - Optimize Dockerfile: multi-stage build, non-root user, minimal base image (distroless).
   - Add image build/push targets to Makefile.

4. **RBAC**:
   - Verify generated RBAC covers all required permissions.
   - Add documentation comments to ClusterRole rules.

**Files created/modified:**
- `charts/vc-operator/Chart.yaml`
- `charts/vc-operator/values.yaml`
- `charts/vc-operator/templates/deployment.yaml`
- `charts/vc-operator/templates/rbac.yaml`
- `charts/vc-operator/templates/serviceaccount.yaml`
- `charts/vc-operator/templates/crds.yaml`
- `charts/vc-operator/templates/NOTES.txt`
- `charts/vc-operator/templates/_helpers.tpl`
- `Dockerfile` (optimize)
- `config/manager/manager.yaml` (resource limits)
- `config/rbac/` (verify)

**Acceptance criteria:**
- `helm template` renders valid Kubernetes manifests.
- `helm lint` passes without errors.
- CRDs are installable via `make install` and via the Helm chart.
- Dockerfile builds successfully and produces a minimal image.

---

### Step 9: Integration Tests with Keycloak

Write end-to-end integration tests that verify the full credential lifecycle using a real Keycloak instance.

**What to do:**

1. **Test infrastructure** (`test/e2e/`):
   - Use testcontainers-go to spin up a Keycloak container with OID4VCI support.
   - Configure Keycloak realm, client, and credential configuration via the Admin REST API.
   - Use envtest for the Kubernetes API server.

2. **Test scenarios**:
   - **Happy path**: Create CredentialIssuer + VerifiableCredentialRequest → verify credential appears in target Secret.
   - **Credential format variants**: Test `jwt_vc_json` format.
   - **Auth failure**: Invalid client credentials → CR enters Error state.
   - **Issuer unavailable**: Keycloak down → CR retries with backoff.
   - **Credential renewal**: Issue a short-lived credential, wait, verify renewal occurs.
   - **CR deletion**: Delete VerifiableCredentialRequest → target Secret is cleaned up.

3. **Test helpers**:
   - Keycloak setup helper (create realm, register client, configure VC issuance).
   - Assertion helpers for checking Secret contents and CR status conditions.

**Files created/modified:**
- `test/e2e/suite_test.go` (test suite setup)
- `test/e2e/keycloak_setup_test.go` (Keycloak container + configuration)
- `test/e2e/credential_lifecycle_test.go` (end-to-end test scenarios)
- `test/e2e/helpers_test.go` (assertion and utility helpers)

**Acceptance criteria:**
- All e2e tests pass against a real Keycloak instance (containerized).
- Tests are skippable via build tag (`//go:build e2e`) for fast CI.
- Test coverage includes happy path, error paths, and renewal.
- Tests clean up all created resources after completion.

---

### Step 10: Documentation and Example Configurations

Write user-facing documentation and provide ready-to-use example configurations.

**What to do:**

1. **README.md**:
   - Project overview and architecture diagram (text-based).
   - Quick start guide (install CRDs, deploy operator, create first credential).
   - CRD reference (fields, defaults, examples).
   - Configuration reference (environment variables, flags).
   - Troubleshooting guide (common error conditions and resolutions).

2. **Example configurations** (`config/samples/`):
   - Complete Keycloak example: CredentialIssuer + auth Secret + VerifiableCredentialRequest.
   - Example with custom renewal interval.
   - Example with additional claims.

3. **Developer documentation**:
   - Contributing guide (build, test, lint instructions).
   - Architecture decision records for key choices (Go/kubebuilder, `CredentialStore` interface for pluggable storage backends, OID4VCI flow selection).

**Files created/modified:**
- `README.md`
- `config/samples/keycloak-example/` (complete working example)
- `docs/architecture.md`
- `CONTRIBUTING.md`

**Acceptance criteria:**
- README contains a working quick-start that a user can follow.
- All sample manifests are valid YAML and pass dry-run validation.
- Architecture decisions are documented with rationale.
