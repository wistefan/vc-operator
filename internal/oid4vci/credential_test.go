package oid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestRequestCredential(t *testing.T) {
	tests := []struct {
		name            string
		accessToken     string
		request         CredentialRequest
		serverResponse  *CredentialResponse
		statusCode      int
		errorResponse   string
		wantErr         bool
		wantErrContain  string
		validateRequest func(t *testing.T, r *http.Request, body []byte)
	}{
		{
			name:        "successful JWT credential request",
			accessToken: "access-token-123",
			request: CredentialRequest{
				CredentialConfigurationID: "UniversityDegree",
				Format:                    "jwt_vc_json",
				Proof: &CredentialProof{
					ProofType: ProofTypeJWT,
					JWT:       "eyJhbGciOiJFUzI1NiJ9.test.signature",
				},
			},
			serverResponse: &CredentialResponse{
				Credential: "eyJhbGciOiJFUzI1NiJ9.credential-payload.signature",
				Format:     "jwt_vc_json",
				CNonce:     "new-nonce",
			},
			statusCode: http.StatusOK,
			validateRequest: func(t *testing.T, r *http.Request, body []byte) {
				t.Helper()
				if r.Header.Get("Authorization") != "Bearer access-token-123" {
					t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
				}
				if r.Header.Get("Content-Type") != ContentTypeJSON {
					t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
				}
				var req CredentialRequest
				if err := json.Unmarshal(body, &req); err != nil {
					t.Fatalf("failed to parse request body: %v", err)
				}
				if req.CredentialConfigurationID != "UniversityDegree" {
					t.Errorf("CredentialConfigurationID: got %s, want UniversityDegree", req.CredentialConfigurationID)
				}
			},
		},
		{
			name:        "credential request with credential definition",
			accessToken: "token-456",
			request: CredentialRequest{
				CredentialConfigurationID: "EmployeeBadge",
				Format:                    "ldp_vc",
				CredentialDefinition: &CredentialDefinition{
					Type:    []string{"VerifiableCredential", "EmployeeBadge"},
					Context: []string{"https://www.w3.org/2018/credentials/v1"},
				},
			},
			serverResponse: &CredentialResponse{
				Credential: map[string]any{
					"@context": []any{"https://www.w3.org/2018/credentials/v1"},
					"type":     []any{"VerifiableCredential", "EmployeeBadge"},
				},
				Format: "ldp_vc",
			},
			statusCode: http.StatusOK,
		},
		{
			name:        "credential request without proof",
			accessToken: "token-no-proof",
			request: CredentialRequest{
				CredentialConfigurationID: "SimpleCredential",
				Format:                    "jwt_vc_json",
			},
			serverResponse: &CredentialResponse{
				Credential: "simple-credential-jwt",
				Format:     "jwt_vc_json",
			},
			statusCode: http.StatusOK,
		},
		{
			name:        "server returns 400 error",
			accessToken: "token-err",
			request: CredentialRequest{
				CredentialConfigurationID: "Unknown",
			},
			statusCode:     http.StatusBadRequest,
			errorResponse:  `{"error":"invalid_credential_request","error_description":"unsupported credential type"}`,
			wantErr:        true,
			wantErrContain: "failed to request credential",
		},
		{
			name:        "server returns 401 unauthorized",
			accessToken: "expired-token",
			request: CredentialRequest{
				CredentialConfigurationID: "Test",
			},
			statusCode:     http.StatusUnauthorized,
			errorResponse:  `{"error":"invalid_token","error_description":"access token expired"}`,
			wantErr:        true,
			wantErrContain: "failed to request credential",
		},
		{
			name:        "server returns invalid JSON",
			accessToken: "token",
			request: CredentialRequest{
				CredentialConfigurationID: "Test",
			},
			statusCode:     http.StatusOK,
			errorResponse:  `{invalid`,
			wantErr:        true,
			wantErrContain: "invalid response from server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("unexpected method: got %s, want POST", r.Method)
				}

				if tt.validateRequest != nil {
					body := make([]byte, r.ContentLength)
					_, _ = r.Body.Read(body)
					tt.validateRequest(t, r, body)
				}

				w.Header().Set("Content-Type", ContentTypeJSON)
				w.WriteHeader(tt.statusCode)

				if tt.serverResponse != nil {
					if err := json.NewEncoder(w).Encode(tt.serverResponse); err != nil {
						t.Fatalf("failed to encode response: %v", err)
					}
				} else if tt.errorResponse != "" {
					_, _ = w.Write([]byte(tt.errorResponse))
				}
			}))
			defer server.Close()

			client := NewClient(WithHTTPClient(server.Client()))
			resp, err := client.RequestCredential(context.Background(), server.URL+"/credential", tt.accessToken, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantErrContain != "" && !containsString(err.Error(), tt.wantErrContain) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Format != tt.serverResponse.Format {
				t.Errorf("Format: got %s, want %s", resp.Format, tt.serverResponse.Format)
			}
			if resp.Credential == nil {
				t.Error("Credential should not be nil")
			}
		})
	}
}

func TestCredentialResponse_CredentialAsString(t *testing.T) {
	tests := []struct {
		name       string
		credential any
		want       string
	}{
		{
			name:       "string credential (JWT)",
			credential: "eyJhbGciOiJFUzI1NiJ9.payload.sig",
			want:       "eyJhbGciOiJFUzI1NiJ9.payload.sig",
		},
		{
			name:       "non-string credential (JSON-LD)",
			credential: map[string]any{"type": "VerifiableCredential"},
			want:       "",
		},
		{
			name:       "nil credential",
			credential: nil,
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &CredentialResponse{Credential: tt.credential}
			got := resp.CredentialAsString()
			if got != tt.want {
				t.Errorf("CredentialAsString: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateProofJWT(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name      string
		issuerURL string
		cNonce    string
	}{
		{
			name:      "standard proof JWT",
			issuerURL: "https://issuer.example.com",
			cNonce:    "nonce-123",
		},
		{
			name:      "proof JWT with empty nonce",
			issuerURL: "https://issuer.example.com",
			cNonce:    "",
		},
		{
			name:      "proof JWT with complex issuer URL",
			issuerURL: "https://auth.complex-domain.example.com/realms/test",
			cNonce:    "complex-nonce-456-xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := GenerateProofJWT(privateKey, tt.issuerURL, tt.cNonce)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tokenString == "" {
				t.Fatal("generated token should not be empty")
			}

			// Parse and verify the JWT
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			if err != nil {
				t.Fatalf("failed to parse generated JWT: %v", err)
			}

			// Verify header
			if token.Header["typ"] != JWTProofHeaderType {
				t.Errorf("JWT typ header: got %v, want %s", token.Header["typ"], JWTProofHeaderType)
			}
			if token.Header["alg"] != ProofAlgorithmES256 {
				t.Errorf("JWT alg header: got %v, want %s", token.Header["alg"], ProofAlgorithmES256)
			}
			jwk, ok := token.Header["jwk"]
			if !ok {
				t.Fatal("JWT should have jwk header")
			}
			jwkMap, ok := jwk.(map[string]any)
			if !ok {
				t.Fatal("jwk header should be a map")
			}
			if jwkMap["kty"] != "EC" {
				t.Errorf("JWK kty: got %v, want EC", jwkMap["kty"])
			}
			if jwkMap["crv"] != "P-256" {
				t.Errorf("JWK crv: got %v, want P-256", jwkMap["crv"])
			}

			// Verify claims
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				t.Fatal("claims should be MapClaims")
			}

			// Check audience - jwt v5 parses aud as []string
			aud, err := claims.GetAudience()
			if err != nil {
				t.Fatalf("failed to get audience: %v", err)
			}
			if len(aud) != 1 || aud[0] != tt.issuerURL {
				t.Errorf("audience: got %v, want [%s]", aud, tt.issuerURL)
			}

			if claims[ClaimNonce] != tt.cNonce {
				t.Errorf("nonce claim: got %v, want %s", claims[ClaimNonce], tt.cNonce)
			}

			iat, err := claims.GetIssuedAt()
			if err != nil {
				t.Fatalf("failed to get issued at: %v", err)
			}
			if iat == nil {
				t.Error("iat claim should be present")
			}
		})
	}
}

func TestVerifyProofJWT(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Generate a valid proof JWT
	tokenString, err := GenerateProofJWT(privateKey, "https://issuer.example.com", "test-nonce")
	if err != nil {
		t.Fatalf("failed to generate proof JWT: %v", err)
	}

	// Verify the proof JWT using the verify function
	claims, err := VerifyProofJWT(tokenString)
	if err != nil {
		t.Fatalf("failed to verify proof JWT: %v", err)
	}

	if claims[ClaimNonce] != "test-nonce" {
		t.Errorf("nonce: got %v, want test-nonce", claims[ClaimNonce])
	}
}

func TestVerifyProofJWT_InvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "malformed token",
			token: "not-a-jwt",
		},
		{
			name:  "empty token",
			token: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyProofJWT(tt.token)
			if err == nil {
				t.Fatal("expected error for invalid token, got nil")
			}
		})
	}
}

func TestGenerateAndVerifyProofJWT_RoundTrip(t *testing.T) {
	// This tests the full round-trip: generate a proof JWT, then verify it
	// using the public key extracted from the JWT's jwk header.
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	issuerURL := "https://issuer.example.com"
	cNonce := "round-trip-nonce"

	tokenString, err := GenerateProofJWT(km.PrivateKey(), issuerURL, cNonce)
	if err != nil {
		t.Fatalf("failed to generate proof JWT: %v", err)
	}

	claims, err := VerifyProofJWT(tokenString)
	if err != nil {
		t.Fatalf("failed to verify proof JWT: %v", err)
	}

	// Verify all expected claims are present and correct
	aud, ok := claims[ClaimAudience]
	if !ok {
		t.Fatal("audience claim should be present")
	}
	// jwt v5 may parse single audience as string
	switch v := aud.(type) {
	case string:
		if v != issuerURL {
			t.Errorf("audience: got %s, want %s", v, issuerURL)
		}
	case []any:
		if len(v) != 1 || v[0] != issuerURL {
			t.Errorf("audience: got %v, want [%s]", v, issuerURL)
		}
	default:
		t.Errorf("unexpected audience type: %T", aud)
	}

	if claims[ClaimNonce] != cNonce {
		t.Errorf("nonce: got %v, want %s", claims[ClaimNonce], cNonce)
	}
}
