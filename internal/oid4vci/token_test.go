package oid4vci

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObtainAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		auth           TokenAuth
		serverResponse *TokenResponse
		statusCode     int
		errorResponse  string
		wantErr        bool
		wantErrContain string
		validateForm   func(t *testing.T, values map[string]string)
	}{
		{
			name: "client_credentials grant success",
			auth: TokenAuth{
				GrantType:    GrantTypeClientCredentials,
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       []string{"openid", "credential"},
			},
			serverResponse: &TokenResponse{
				AccessToken:     "access-token-123",
				TokenType:       "Bearer",
				ExpiresIn:       3600,
				CNonce:          "nonce-abc",
				CNonceExpiresIn: 300,
			},
			statusCode: http.StatusOK,
			validateForm: func(t *testing.T, values map[string]string) {
				t.Helper()
				assertFormValue(t, values, FormFieldGrantType, string(GrantTypeClientCredentials))
				assertFormValue(t, values, FormFieldClientID, "my-client")
				assertFormValue(t, values, FormFieldClientSecret, "my-secret")
				assertFormValue(t, values, FormFieldScope, "openid credential")
			},
		},
		{
			name: "client_credentials without scopes",
			auth: TokenAuth{
				GrantType:    GrantTypeClientCredentials,
				ClientID:     "client-no-scope",
				ClientSecret: "secret-no-scope",
			},
			serverResponse: &TokenResponse{
				AccessToken: "token-no-scope",
				TokenType:   "Bearer",
			},
			statusCode: http.StatusOK,
			validateForm: func(t *testing.T, values map[string]string) {
				t.Helper()
				assertFormValue(t, values, FormFieldGrantType, string(GrantTypeClientCredentials))
				if _, ok := values[FormFieldScope]; ok {
					t.Error("scope should not be set when no scopes requested")
				}
			},
		},
		{
			name: "pre-authorized_code grant success",
			auth: TokenAuth{
				GrantType:         GrantTypePreAuthorizedCode,
				PreAuthorizedCode: "pre-auth-code-xyz",
			},
			serverResponse: &TokenResponse{
				AccessToken: "pre-auth-token-456",
				TokenType:   "Bearer",
				CNonce:      "nonce-def",
			},
			statusCode: http.StatusOK,
			validateForm: func(t *testing.T, values map[string]string) {
				t.Helper()
				assertFormValue(t, values, FormFieldGrantType, string(GrantTypePreAuthorizedCode))
				assertFormValue(t, values, FormFieldPreAuthorizedCode, "pre-auth-code-xyz")
			},
		},
		{
			name: "pre-authorized_code with client ID",
			auth: TokenAuth{
				GrantType:         GrantTypePreAuthorizedCode,
				PreAuthorizedCode: "pre-auth-code-789",
				ClientID:          "optional-client",
			},
			serverResponse: &TokenResponse{
				AccessToken: "pre-auth-token-789",
				TokenType:   "Bearer",
			},
			statusCode: http.StatusOK,
			validateForm: func(t *testing.T, values map[string]string) {
				t.Helper()
				assertFormValue(t, values, FormFieldGrantType, string(GrantTypePreAuthorizedCode))
				assertFormValue(t, values, FormFieldPreAuthorizedCode, "pre-auth-code-789")
				assertFormValue(t, values, FormFieldClientID, "optional-client")
			},
		},
		{
			name: "server returns 401 unauthorized",
			auth: TokenAuth{
				GrantType:    GrantTypeClientCredentials,
				ClientID:     "bad-client",
				ClientSecret: "bad-secret",
			},
			statusCode:     http.StatusUnauthorized,
			errorResponse:  `{"error":"invalid_client","error_description":"client authentication failed"}`,
			wantErr:        true,
			wantErrContain: "failed to obtain access token",
		},
		{
			name: "server returns 400 bad request",
			auth: TokenAuth{
				GrantType:    GrantTypeClientCredentials,
				ClientID:     "client",
				ClientSecret: "secret",
			},
			statusCode:     http.StatusBadRequest,
			errorResponse:  `{"error":"invalid_grant","error_description":"grant type not supported"}`,
			wantErr:        true,
			wantErrContain: "failed to obtain access token",
		},
		{
			name: "server returns invalid JSON",
			auth: TokenAuth{
				GrantType:    GrantTypeClientCredentials,
				ClientID:     "client",
				ClientSecret: "secret",
			},
			statusCode:     http.StatusOK,
			errorResponse:  `{not valid json`,
			wantErr:        true,
			wantErrContain: "invalid response from server",
		},
		{
			name: "unsupported grant type",
			auth: TokenAuth{
				GrantType: GrantType("unsupported_grant"),
			},
			wantErr:        true,
			wantErrContain: "unsupported grant type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			if tt.auth.GrantType == GrantType("unsupported_grant") {
				// For unsupported grant type, we don't need a server
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Fatal("server should not be called for unsupported grant type")
				}))
			} else {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify method and content type
					if r.Method != http.MethodPost {
						t.Errorf("unexpected method: got %s, want POST", r.Method)
					}
					if r.Header.Get("Content-Type") != ContentTypeFormURLEncoded {
						t.Errorf("unexpected Content-Type: got %s, want %s", r.Header.Get("Content-Type"), ContentTypeFormURLEncoded)
					}

					// Parse form values for validation
					if err := r.ParseForm(); err != nil {
						t.Fatalf("failed to parse form: %v", err)
					}
					if tt.validateForm != nil {
						formValues := make(map[string]string)
						for k, v := range r.PostForm {
							if len(v) > 0 {
								formValues[k] = v[0]
							}
						}
						tt.validateForm(t, formValues)
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
			}
			defer server.Close()

			client := NewClient(WithHTTPClient(server.Client()))
			tokenResp, err := client.ObtainAccessToken(context.Background(), server.URL+"/token", tt.auth)

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

			if tokenResp.AccessToken != tt.serverResponse.AccessToken {
				t.Errorf("AccessToken: got %s, want %s", tokenResp.AccessToken, tt.serverResponse.AccessToken)
			}
			if tokenResp.TokenType != tt.serverResponse.TokenType {
				t.Errorf("TokenType: got %s, want %s", tokenResp.TokenType, tt.serverResponse.TokenType)
			}
			if tokenResp.CNonce != tt.serverResponse.CNonce {
				t.Errorf("CNonce: got %s, want %s", tokenResp.CNonce, tt.serverResponse.CNonce)
			}
			if tokenResp.ExpiresIn != tt.serverResponse.ExpiresIn {
				t.Errorf("ExpiresIn: got %d, want %d", tokenResp.ExpiresIn, tt.serverResponse.ExpiresIn)
			}
			if tokenResp.CNonceExpiresIn != tt.serverResponse.CNonceExpiresIn {
				t.Errorf("CNonceExpiresIn: got %d, want %d", tokenResp.CNonceExpiresIn, tt.serverResponse.CNonceExpiresIn)
			}
		})
	}
}

func TestBuildTokenFormData(t *testing.T) {
	tests := []struct {
		name      string
		auth      TokenAuth
		wantErr   bool
		wantKeys  []string
		wantGrant string
	}{
		{
			name: "client credentials populates correct fields",
			auth: TokenAuth{
				GrantType:    GrantTypeClientCredentials,
				ClientID:     "client",
				ClientSecret: "secret",
				Scopes:       []string{"scope1"},
			},
			wantKeys:  []string{FormFieldGrantType, FormFieldClientID, FormFieldClientSecret, FormFieldScope},
			wantGrant: string(GrantTypeClientCredentials),
		},
		{
			name: "pre-authorized code populates correct fields",
			auth: TokenAuth{
				GrantType:         GrantTypePreAuthorizedCode,
				PreAuthorizedCode: "code",
			},
			wantKeys:  []string{FormFieldGrantType, FormFieldPreAuthorizedCode},
			wantGrant: string(GrantTypePreAuthorizedCode),
		},
		{
			name: "unknown grant type returns error",
			auth: TokenAuth{
				GrantType: GrantType("unknown"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form, err := buildTokenFormData(tt.auth)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if form.Get(FormFieldGrantType) != tt.wantGrant {
				t.Errorf("grant_type: got %s, want %s", form.Get(FormFieldGrantType), tt.wantGrant)
			}

			for _, key := range tt.wantKeys {
				if form.Get(key) == "" {
					t.Errorf("expected form key %q to be present", key)
				}
			}
		})
	}
}

// assertFormValue is a test helper that checks a form value matches the expected value.
func assertFormValue(t *testing.T, values map[string]string, key, expected string) {
	t.Helper()
	if got, ok := values[key]; !ok {
		t.Errorf("form field %q not present", key)
	} else if got != expected {
		t.Errorf("form field %q: got %q, want %q", key, got, expected)
	}
}
