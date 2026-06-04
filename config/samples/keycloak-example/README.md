# Keycloak Example

This directory contains a complete working example that demonstrates how to use
the vc-operator with a Keycloak instance as the OID4VCI credential issuer.

## Prerequisites

- A running Kubernetes cluster with the vc-operator deployed.
- A Keycloak instance with OID4VCI support configured (Keycloak 24+ with the
  Verifiable Credentials feature enabled).
- A Keycloak realm configured for credential issuance with a registered client.

## Files

| File | Description |
|------|-------------|
| `auth-secret.yaml` | Kubernetes Secret with Keycloak client credentials. |
| `credential-issuer.yaml` | `CredentialIssuer` pointing to the Keycloak realm. |
| `vcrequest.yaml` | `VerifiableCredentialRequest` for a basic credential. |
| `vcrequest-custom-renewal.yaml` | Request with a custom 1-hour renewal buffer. |
| `vcrequest-additional-claims.yaml` | Request with additional issuer-specific claims. |
| `kustomization.yaml` | Kustomize overlay to apply all base resources. |

## Usage

### 1. Configure the auth Secret

Edit `auth-secret.yaml` and replace the placeholder values with your actual
Keycloak client credentials:

```bash
# Encode your credentials
echo -n "my-vc-client" | base64
echo -n "my-client-secret" | base64
```

Update the `client_id` and `client_secret` fields in `auth-secret.yaml` with
the base64-encoded values.

### 2. Update the issuer URL

Edit `credential-issuer.yaml` and set `spec.issuerURL` to your Keycloak realm
URL (e.g., `https://keycloak.example.com/realms/vc-issuer`).

### 3. Apply the base resources

```bash
# Apply the auth Secret, CredentialIssuer, and basic VerifiableCredentialRequest
kubectl apply -k config/samples/keycloak-example/
```

### 4. Verify

```bash
# Check the CredentialIssuer is ready
kubectl get credentialissuer keycloak-issuer

# Check the VerifiableCredentialRequest status
kubectl get verifiablecredentialrequest my-vc-request

# Inspect the generated Secret
kubectl get secret my-service-vc -o yaml
```

### 5. Try additional examples

Apply a request with custom renewal interval:

```bash
kubectl apply -f config/samples/keycloak-example/vcrequest-custom-renewal.yaml
```

Apply a request with additional claims:

```bash
kubectl apply -f config/samples/keycloak-example/vcrequest-additional-claims.yaml
```

## Cleanup

```bash
kubectl delete -k config/samples/keycloak-example/
# Additional examples (if applied separately)
kubectl delete -f config/samples/keycloak-example/vcrequest-custom-renewal.yaml
kubectl delete -f config/samples/keycloak-example/vcrequest-additional-claims.yaml
```
