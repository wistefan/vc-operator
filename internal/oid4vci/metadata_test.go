package oid4vci

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDiscoverMetadata(t *testing.T) {
	tests := []struct {
		name           string
		metadata       *IssuerMetadata
		statusCode     int
		responseBody   string
		wantErr        bool
		wantErrContain string
	}{
		{
			name: "successful metadata discovery with all fields",
			metadata: &IssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				TokenEndpoint:      "https://issuer.example.com/token",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"UniversityDegree": {
						Format:                               "jwt_vc_json",
						Scope:                                "university_degree",
						CryptographicBindingMethodsSupported: []string{"did:key"},
						ProofTypesSupported: map[string]ProofTypeConfig{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256"},
							},
						},
						CredentialDefinition: &CredentialDefinition{
							Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
						},
					},
				},
			},
			statusCode: http.StatusOK,
		},
		{
			name: "metadata with authorization server",
			metadata: &IssuerMetadata{
				CredentialIssuer:    "https://issuer.example.com",
				CredentialEndpoint:  "https://issuer.example.com/credential",
				AuthorizationServer: "https://auth.example.com",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"EmployeeBadge": {
						Format: "ldp_vc",
					},
				},
			},
			statusCode: http.StatusOK,
		},
		{
			name: "metadata with multiple credential configurations",
			metadata: &IssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				TokenEndpoint:      "https://issuer.example.com/token",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"TypeA": {Format: "jwt_vc_json"},
					"TypeB": {Format: "ldp_vc"},
					"TypeC": {Format: "vc+sd-jwt"},
				},
			},
			statusCode: http.StatusOK,
		},
		{
			name:           "server returns 404",
			statusCode:     http.StatusNotFound,
			responseBody:   `{"error":"not_found","error_description":"metadata endpoint not found"}`,
			wantErr:        true,
			wantErrContain: "failed to fetch issuer metadata",
		},
		{
			name:           "server returns 500",
			statusCode:     http.StatusInternalServerError,
			responseBody:   `{"error":"server_error"}`,
			wantErr:        true,
			wantErrContain: "failed to fetch issuer metadata",
		},
		{
			name:           "server returns invalid JSON",
			statusCode:     http.StatusOK,
			responseBody:   `{invalid json`,
			wantErr:        true,
			wantErrContain: "invalid response from server",
		},
		{
			name:           "server returns empty body",
			statusCode:     http.StatusOK,
			responseBody:   ``,
			wantErr:        true,
			wantErrContain: "invalid response from server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the request path
				if r.URL.Path != WellKnownPath {
					t.Errorf("unexpected request path: got %s, want %s", r.URL.Path, WellKnownPath)
				}

				// Verify Accept header
				if r.Header.Get("Accept") != ContentTypeJSON {
					t.Errorf("unexpected Accept header: got %s, want %s", r.Header.Get("Accept"), ContentTypeJSON)
				}

				// Verify method
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method: got %s, want GET", r.Method)
				}

				w.Header().Set("Content-Type", ContentTypeJSON)
				w.WriteHeader(tt.statusCode)

				if tt.metadata != nil {
					if err := json.NewEncoder(w).Encode(tt.metadata); err != nil {
						t.Fatalf("failed to encode metadata: %v", err)
					}
				} else if tt.responseBody != "" {
					_, _ = w.Write([]byte(tt.responseBody))
				}
			}))
			defer server.Close()

			client := NewClient(WithHTTPClient(server.Client()))
			metadata, err := client.DiscoverMetadata(context.Background(), server.URL)

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

			if metadata.CredentialIssuer != tt.metadata.CredentialIssuer {
				t.Errorf("CredentialIssuer: got %s, want %s", metadata.CredentialIssuer, tt.metadata.CredentialIssuer)
			}
			if metadata.CredentialEndpoint != tt.metadata.CredentialEndpoint {
				t.Errorf("CredentialEndpoint: got %s, want %s", metadata.CredentialEndpoint, tt.metadata.CredentialEndpoint)
			}
			if metadata.TokenEndpoint != tt.metadata.TokenEndpoint {
				t.Errorf("TokenEndpoint: got %s, want %s", metadata.TokenEndpoint, tt.metadata.TokenEndpoint)
			}
			if len(metadata.CredentialConfigurationsSupported) != len(tt.metadata.CredentialConfigurationsSupported) {
				t.Errorf("CredentialConfigurationsSupported count: got %d, want %d",
					len(metadata.CredentialConfigurationsSupported), len(tt.metadata.CredentialConfigurationsSupported))
			}
		})
	}
}

func TestDiscoverMetadata_TrailingSlash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownPath {
			t.Errorf("unexpected path: got %s, want %s", r.URL.Path, WellKnownPath)
		}
		w.Header().Set("Content-Type", ContentTypeJSON)
		_ = json.NewEncoder(w).Encode(IssuerMetadata{
			CredentialIssuer:   "https://issuer.example.com",
			CredentialEndpoint: "https://issuer.example.com/credential",
		})
	}))
	defer server.Close()

	client := NewClient(WithHTTPClient(server.Client()))
	// URL with trailing slash should still work
	_, err := client.DiscoverMetadata(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDiscoverMetadata_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow server
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(WithHTTPClient(server.Client()))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.DiscoverMetadata(ctx, server.URL)
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
}

func TestDiscoverMetadata_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.DiscoverMetadata(context.Background(), "://invalid-url")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// containsString checks if s contains substr. Used in test assertions.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
