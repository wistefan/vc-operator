//go:build integration

/*
Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
and other contributors as indicated by the @author tags.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package integration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"
)

// Mock OID4VCI issuer constants define default values used by the mock
// server to simulate a Keycloak-like OID4VCI credential issuer.
const (
	// defaultValidClientID is the client identifier accepted by the mock token endpoint.
	defaultValidClientID = "test-client"

	// defaultValidClientSecret is the client secret accepted by the mock token endpoint.
	defaultValidClientSecret = "test-secret"

	// defaultCredentialType is the credential type advertised in issuer metadata.
	defaultCredentialType = "VerifiableCredential"

	// defaultCredentialFormat is the credential format used by the mock issuer.
	defaultCredentialFormat = "jwt_vc_json"

	// defaultCredentialExpiry is the default credential validity period.
	defaultCredentialExpiry = 1 * time.Hour

	// defaultAccessToken is the static access token returned by the mock token endpoint.
	defaultAccessToken = "mock-access-token-xyz"

	// defaultCNonce is the c_nonce value returned by the mock token endpoint.
	defaultCNonce = "mock-c-nonce-abc"

	// mockTokenExpiresIn is the token expiry in seconds returned by the mock.
	mockTokenExpiresIn = 3600
)

// MockOID4VCIIssuer is a mock OID4VCI credential issuer backed by an
// httptest.Server. It simulates the metadata discovery, token, and
// credential endpoints of a Keycloak instance with OID4VCI support.
//
// The mock supports configurable failure modes for testing error paths:
// setting failToken or failCredential causes the respective endpoints
// to return error responses.
type MockOID4VCIIssuer struct {
	// Server is the underlying httptest.Server.
	Server *httptest.Server

	mu               sync.Mutex
	validClientID    string
	validClientSecret string
	credentialExpiry time.Duration
	failToken        bool
	failCredential   bool

	// issueCount tracks the number of credentials issued (atomic).
	issueCount atomic.Int32
}

// NewMockOID4VCIIssuer creates and starts a new mock OID4VCI issuer.
// The server starts immediately on a random localhost port. The issuer
// accepts the default client credentials and returns JWT VCs with the
// configured expiry duration.
func NewMockOID4VCIIssuer() *MockOID4VCIIssuer {
	m := &MockOID4VCIIssuer{
		validClientID:    defaultValidClientID,
		validClientSecret: defaultValidClientSecret,
		credentialExpiry: defaultCredentialExpiry,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-credential-issuer", m.handleMetadata)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/credential", m.handleCredential)

	m.Server = httptest.NewServer(mux)
	return m
}

// URL returns the base URL of the mock OID4VCI issuer. This should be
// used as the IssuerURL in CredentialIssuer CRs.
func (m *MockOID4VCIIssuer) URL() string {
	return m.Server.URL
}

// Stop shuts down the mock OID4VCI issuer server.
func (m *MockOID4VCIIssuer) Stop() {
	if m.Server != nil {
		m.Server.Close()
	}
}

// SetFailToken configures whether the token endpoint should always return
// an HTTP 401 error. When true, any token request will fail regardless
// of the credentials provided.
func (m *MockOID4VCIIssuer) SetFailToken(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failToken = fail
}

// SetFailCredential configures whether the credential endpoint should
// always return an HTTP 500 error. When true, any credential request
// will fail regardless of the access token provided.
func (m *MockOID4VCIIssuer) SetFailCredential(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failCredential = fail
}

// SetCredentialExpiry configures the expiry duration for newly issued
// credentials. The credential's "exp" claim will be set to
// time.Now() + expiry at the time of issuance.
func (m *MockOID4VCIIssuer) SetCredentialExpiry(expiry time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.credentialExpiry = expiry
}

// IssueCount returns the total number of credentials issued by the mock
// server since creation. This counter is monotonically increasing and
// useful for verifying that renewal occurred (count > 1).
func (m *MockOID4VCIIssuer) IssueCount() int32 {
	return m.issueCount.Load()
}

// ResetIssueCount resets the credential issue counter to zero.
func (m *MockOID4VCIIssuer) ResetIssueCount() {
	m.issueCount.Store(0)
}

// handleMetadata serves the OID4VCI credential issuer metadata at the
// well-known endpoint. The metadata includes the token and credential
// endpoint URLs pointing to this mock server.
func (m *MockOID4VCIIssuer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := map[string]interface{}{
		"credential_issuer":   m.Server.URL,
		"credential_endpoint": m.Server.URL + "/credential",
		"token_endpoint":      m.Server.URL + "/token",
		"credential_configurations_supported": map[string]interface{}{
			defaultCredentialType: map[string]interface{}{
				"format": defaultCredentialFormat,
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
				"proof_types_supported": map[string]interface{}{
					"jwt": map[string]interface{}{
						"proof_signing_alg_values_supported": []string{"ES256"},
					},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		http.Error(w, "failed to encode metadata", http.StatusInternalServerError)
	}
}

// handleToken serves the OAuth 2.0 token endpoint. It validates client
// credentials against the configured valid values and returns an access
// token with a c_nonce on success, or a 401 error on failure.
func (m *MockOID4VCIIssuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	m.mu.Lock()
	failToken := m.failToken
	validID := m.validClientID
	validSecret := m.validClientSecret
	m.mu.Unlock()

	// Check if forced failure is configured.
	if failToken {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Token endpoint forced failure")
		return
	}

	// Parse form data and validate credentials.
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID != validID || clientSecret != validSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// Return a successful token response.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": defaultAccessToken,
		"token_type":   "Bearer",
		"expires_in":   mockTokenExpiresIn,
		"c_nonce":      defaultCNonce,
	}); err != nil {
		http.Error(w, "failed to encode token response", http.StatusInternalServerError)
	}
}

// handleCredential serves the OID4VCI credential endpoint. It validates
// the Bearer token, generates a JWT VC with the configured expiry, and
// increments the issue counter.
func (m *MockOID4VCIIssuer) handleCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	m.mu.Lock()
	failCred := m.failCredential
	expiry := m.credentialExpiry
	m.mu.Unlock()

	// Check if forced failure is configured.
	if failCred {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": "Credential endpoint forced failure",
		})
		return
	}

	// Validate the Bearer token.
	authHeader := r.Header.Get("Authorization")
	expectedAuth := "Bearer " + defaultAccessToken
	if authHeader != expectedAuth {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "Invalid or missing access token",
		})
		return
	}

	// Generate a JWT VC with the configured expiry.
	count := m.issueCount.Add(1)
	now := time.Now()
	jwtVC := buildTestJWT(m.Server.URL, now, now.Add(expiry), count)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"credential": jwtVC,
		"format":     defaultCredentialFormat,
	}); err != nil {
		http.Error(w, "failed to encode credential response", http.StatusInternalServerError)
	}
}

// writeTokenError writes a standard OAuth 2.0 error response to the
// HTTP response writer with the specified status code and error details.
func writeTokenError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// buildTestJWT constructs a compact-serialized JWT with the given issuer,
// timestamps, and a counter value for distinguishing credentials across
// renewals. The JWT is not cryptographically signed (uses a dummy
// signature) since the operator's credential parser does not verify
// signatures — it trusts the issuer.
func buildTestJWT(issuer string, iat, exp time.Time, counter int32) string {
	// Header: {"alg":"ES256","typ":"JWT"}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))

	// Payload with standard and VC-specific claims.
	payload := map[string]interface{}{
		"iss":     issuer,
		"sub":     "test-subject",
		"iat":     iat.Unix(),
		"exp":     exp.Unix(),
		"counter": counter,
		"vc": map[string]interface{}{
			"type": []string{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{
				"id":   fmt.Sprintf("did:example:subject-%d", counter),
				"name": "Test Subject",
			},
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Dummy signature (not cryptographically valid — parser skips verification).
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature-placeholder"))

	return header + "." + payloadB64 + "." + signature
}
