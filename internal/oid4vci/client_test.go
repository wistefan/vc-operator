package oid4vci

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestNewClient_WithHTTPClient(t *testing.T) {
	customHTTP := &http.Client{Timeout: 60 * time.Second}
	client := NewClient(WithHTTPClient(customHTTP))
	if client == nil {
		t.Fatal("client should not be nil")
	}

	// Verify the custom client is used by checking the internal field
	impl, ok := client.(*oid4vciClient)
	if !ok {
		t.Fatal("client should be *oid4vciClient")
	}
	if impl.httpClient != customHTTP {
		t.Error("custom HTTP client should be set")
	}
}

func TestNewClient_WithTimeout(t *testing.T) {
	customTimeout := 45 * time.Second
	client := NewClient(WithTimeout(customTimeout))

	impl, ok := client.(*oid4vciClient)
	if !ok {
		t.Fatal("client should be *oid4vciClient")
	}
	if impl.httpClient.Timeout != customTimeout {
		t.Errorf("timeout: got %v, want %v", impl.httpClient.Timeout, customTimeout)
	}
}

// TestFullOID4VCIFlow tests the complete OID4VCI credential issuance flow:
// metadata discovery -> token acquisition -> credential request.
// This integration-style test uses httptest servers to simulate the issuer.
func TestFullOID4VCIFlow(t *testing.T) {
	// Set up a mock OID4VCI server that handles all three endpoints
	mux := http.NewServeMux()

	metadata := IssuerMetadata{
		CredentialIssuer:   "https://issuer.example.com",
		CredentialEndpoint: "/credential", // will be replaced with server URL
		TokenEndpoint:      "/token",      // will be replaced with server URL
		CredentialConfigurationsSupported: map[string]CredentialConfiguration{
			"TestCredential": {
				Format: "jwt_vc_json",
				Scope:  "test_credential",
				ProofTypesSupported: map[string]ProofTypeConfig{
					ProofTypeJWT: {
						ProofSigningAlgValuesSupported: []string{ProofAlgorithmES256},
					},
				},
			},
		},
	}

	// Metadata endpoint
	mux.HandleFunc(WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeJSON)
		_ = json.NewEncoder(w).Encode(metadata)
	})

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", ContentTypeJSON)
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:     "test-access-token",
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			CNonce:          "test-cnonce",
			CNonceExpiresIn: 300,
		})
	})

	// Credential endpoint
	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(OIDCError{
				ErrorCode:        "invalid_token",
				ErrorDescription: "invalid access token",
			})
			return
		}

		w.Header().Set("Content-Type", ContentTypeJSON)
		_ = json.NewEncoder(w).Encode(CredentialResponse{
			Credential: "eyJhbGciOiJFUzI1NiJ9.test-credential-payload.test-signature",
			Format:     "jwt_vc_json",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Update metadata with actual server URLs
	metadata.CredentialEndpoint = server.URL + "/credential"
	metadata.TokenEndpoint = server.URL + "/token"

	client := NewClient(WithHTTPClient(server.Client()))
	ctx := context.Background()

	// Step 1: Discover metadata
	discoveredMetadata, err := client.DiscoverMetadata(ctx, server.URL)
	if err != nil {
		t.Fatalf("DiscoverMetadata failed: %v", err)
	}
	if discoveredMetadata.CredentialIssuer != "https://issuer.example.com" {
		t.Errorf("CredentialIssuer: got %s, want https://issuer.example.com", discoveredMetadata.CredentialIssuer)
	}
	if _, ok := discoveredMetadata.CredentialConfigurationsSupported["TestCredential"]; !ok {
		t.Fatal("TestCredential configuration should be present in metadata")
	}

	// Step 2: Obtain access token
	tokenResp, err := client.ObtainAccessToken(ctx, server.URL+"/token", TokenAuth{
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"test_credential"},
	})
	if err != nil {
		t.Fatalf("ObtainAccessToken failed: %v", err)
	}
	if tokenResp.AccessToken != "test-access-token" {
		t.Errorf("AccessToken: got %s, want test-access-token", tokenResp.AccessToken)
	}
	if tokenResp.CNonce != "test-cnonce" {
		t.Errorf("CNonce: got %s, want test-cnonce", tokenResp.CNonce)
	}

	// Step 3: Generate proof and request credential
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}

	proofJWT, err := GenerateProofJWT(km.PrivateKey(), discoveredMetadata.CredentialIssuer, tokenResp.CNonce, "")
	if err != nil {
		t.Fatalf("GenerateProofJWT failed: %v", err)
	}

	credResp, err := client.RequestCredential(ctx, server.URL+"/credential", tokenResp.AccessToken, CredentialRequest{
		CredentialConfigurationID: "TestCredential",
		Format:                    "jwt_vc_json",
		Proof: &CredentialProof{
			ProofType: ProofTypeJWT,
			JWT:       proofJWT,
		},
	})
	if err != nil {
		t.Fatalf("RequestCredential failed: %v", err)
	}

	credString := credResp.CredentialAsString()
	if credString == "" {
		t.Error("credential should be a non-empty string")
	}
	if credResp.Format != "jwt_vc_json" {
		t.Errorf("Format: got %s, want jwt_vc_json", credResp.Format)
	}
}

// TestFullOID4VCIFlow_PreAuthorizedCode tests the pre-authorized code flow.
func TestFullOID4VCIFlow_PreAuthorizedCode(t *testing.T) {
	mux := http.NewServeMux()

	// Token endpoint expecting pre-authorized code
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		grantType := r.PostFormValue(FormFieldGrantType)
		if grantType != string(GrantTypePreAuthorizedCode) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(OIDCError{
				ErrorCode:        "unsupported_grant_type",
				ErrorDescription: "only pre-authorized_code is supported",
			})
			return
		}
		preAuthCode := r.PostFormValue(FormFieldPreAuthorizedCode)
		if preAuthCode != "valid-pre-auth-code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(OIDCError{
				ErrorCode:        "invalid_grant",
				ErrorDescription: "invalid pre-authorized code",
			})
			return
		}

		w.Header().Set("Content-Type", ContentTypeJSON)
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "pre-auth-access-token",
			TokenType:   "Bearer",
			CNonce:      "pre-auth-cnonce",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(WithHTTPClient(server.Client()))

	tokenResp, err := client.ObtainAccessToken(context.Background(), server.URL+"/token", TokenAuth{
		GrantType:         GrantTypePreAuthorizedCode,
		PreAuthorizedCode: "valid-pre-auth-code",
	})
	if err != nil {
		t.Fatalf("ObtainAccessToken failed: %v", err)
	}
	if tokenResp.AccessToken != "pre-auth-access-token" {
		t.Errorf("AccessToken: got %s, want pre-auth-access-token", tokenResp.AccessToken)
	}
}
