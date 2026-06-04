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

package credential

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// buildJWT constructs a compact-serialized JWT from header and payload maps.
// The signature segment is a fixed placeholder since the parser does not verify signatures.
func buildJWT(header, payload map[string]interface{}) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return headerB64 + "." + payloadB64 + ".signature-placeholder"
}

func TestParseJWTCredential(t *testing.T) {
	now := time.Now()
	expTime := now.Add(1 * time.Hour)
	iatTime := now.Add(-5 * time.Minute)

	tests := []struct {
		name        string
		rawJWT      string
		wantIssuer  string
		wantSubject string
		wantExpiry  bool
		wantIat     bool
		wantVCTypes []string
		wantErr     bool
	}{
		{
			name: "full JWT VC with all standard claims and vc payload",
			rawJWT: buildJWT(
				map[string]interface{}{"alg": "ES256", "typ": "JWT"},
				map[string]interface{}{
					ClaimIss: "https://issuer.example.com",
					ClaimSub: "did:example:holder123",
					ClaimExp: float64(expTime.Unix()),
					ClaimIat: float64(iatTime.Unix()),
					ClaimJti: "urn:uuid:abc-123",
					ClaimVC: map[string]interface{}{
						VCClaimType:    []interface{}{"VerifiableCredential", "UniversityDegreeCredential"},
						VCClaimContext: []interface{}{"https://www.w3.org/2018/credentials/v1"},
						VCClaimCredentialSubject: map[string]interface{}{
							"degree": map[string]interface{}{
								"type": "BachelorDegree",
								"name": "Computer Science",
							},
						},
					},
				},
			),
			wantIssuer:  "https://issuer.example.com",
			wantSubject: "did:example:holder123",
			wantExpiry:  true,
			wantIat:     true,
			wantVCTypes: []string{"VerifiableCredential", "UniversityDegreeCredential"},
			wantErr:     false,
		},
		{
			name: "JWT with only issuer and expiry",
			rawJWT: buildJWT(
				map[string]interface{}{"alg": "ES256"},
				map[string]interface{}{
					ClaimIss: "https://issuer.example.com",
					ClaimExp: float64(expTime.Unix()),
				},
			),
			wantIssuer:  "https://issuer.example.com",
			wantSubject: "",
			wantExpiry:  true,
			wantIat:     false,
			wantVCTypes: nil,
			wantErr:     false,
		},
		{
			name: "JWT without expiry claim",
			rawJWT: buildJWT(
				map[string]interface{}{"alg": "ES256"},
				map[string]interface{}{
					ClaimIss: "https://issuer.example.com",
					ClaimSub: "did:example:subject",
					ClaimIat: float64(iatTime.Unix()),
				},
			),
			wantIssuer:  "https://issuer.example.com",
			wantSubject: "did:example:subject",
			wantExpiry:  false,
			wantIat:     true,
			wantVCTypes: nil,
			wantErr:     false,
		},
		{
			name: "JWT with empty payload (minimal)",
			rawJWT: buildJWT(
				map[string]interface{}{"alg": "none"},
				map[string]interface{}{},
			),
			wantIssuer:  "",
			wantSubject: "",
			wantExpiry:  false,
			wantIat:     false,
			wantVCTypes: nil,
			wantErr:     false,
		},
		{
			name: "JWT with vc claim but no type",
			rawJWT: buildJWT(
				map[string]interface{}{"alg": "ES256"},
				map[string]interface{}{
					ClaimIss: "https://issuer.example.com",
					ClaimVC: map[string]interface{}{
						VCClaimCredentialSubject: map[string]interface{}{
							"name": "Alice",
						},
					},
				},
			),
			wantIssuer:  "https://issuer.example.com",
			wantSubject: "",
			wantExpiry:  false,
			wantIat:     false,
			wantVCTypes: nil,
			wantErr:     false,
		},
		{
			name:    "empty JWT string",
			rawJWT:  "",
			wantErr: true,
		},
		{
			name:    "whitespace-only JWT string",
			rawJWT:  "   ",
			wantErr: true,
		},
		{
			name:    "JWT with wrong segment count (2 segments)",
			rawJWT:  "header.payload",
			wantErr: true,
		},
		{
			name:    "JWT with wrong segment count (4 segments)",
			rawJWT:  "a.b.c.d",
			wantErr: true,
		},
		{
			name:    "JWT with invalid base64 in header",
			rawJWT:  "!!!invalid!!!.eyJ0ZXN0IjoxfQ.sig",
			wantErr: true,
		},
		{
			name: "JWT with invalid JSON in payload",
			rawJWT: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) +
				"." + base64.RawURLEncoding.EncodeToString([]byte(`{not-json`)) +
				".sig",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseJWTCredential(tt.rawJWT)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if parsed.Issuer != tt.wantIssuer {
				t.Errorf("Issuer = %q, want %q", parsed.Issuer, tt.wantIssuer)
			}
			if parsed.Subject != tt.wantSubject {
				t.Errorf("Subject = %q, want %q", parsed.Subject, tt.wantSubject)
			}
			if tt.wantExpiry && !parsed.HasExpiry() {
				t.Errorf("expected expiry to be set")
			}
			if !tt.wantExpiry && parsed.HasExpiry() {
				t.Errorf("expected no expiry, got %v", parsed.Expiry)
			}
			if tt.wantIat && parsed.IssuedAt.IsZero() {
				t.Errorf("expected IssuedAt to be set")
			}
			if !tt.wantIat && !parsed.IssuedAt.IsZero() {
				t.Errorf("expected no IssuedAt, got %v", parsed.IssuedAt)
			}

			vcTypes := parsed.VCTypes()
			if tt.wantVCTypes == nil {
				if vcTypes != nil {
					t.Errorf("VCTypes = %v, want nil", vcTypes)
				}
			} else {
				if len(vcTypes) != len(tt.wantVCTypes) {
					t.Errorf("VCTypes length = %d, want %d", len(vcTypes), len(tt.wantVCTypes))
				} else {
					for i, v := range vcTypes {
						if v != tt.wantVCTypes[i] {
							t.Errorf("VCTypes[%d] = %q, want %q", i, v, tt.wantVCTypes[i])
						}
					}
				}
			}
		})
	}
}

func TestParsedCredential_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		expiry  time.Time
		refTime time.Time
		want    bool
	}{
		{
			name:    "not expired - expiry in the future",
			expiry:  now.Add(1 * time.Hour),
			refTime: now,
			want:    false,
		},
		{
			name:    "expired - expiry in the past",
			expiry:  now.Add(-1 * time.Hour),
			refTime: now,
			want:    true,
		},
		{
			name:    "not expired - no expiry set (zero value)",
			expiry:  time.Time{},
			refTime: now,
			want:    false,
		},
		{
			name:    "expired - exactly at expiry boundary",
			expiry:  now,
			refTime: now.Add(1 * time.Second),
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &ParsedCredential{Expiry: tt.expiry}
			if got := pc.IsExpired(tt.refTime); got != tt.want {
				t.Errorf("IsExpired(%v) = %v, want %v", tt.refTime, got, tt.want)
			}
		})
	}
}

func TestParsedCredential_HasExpiry(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{
			name:   "has expiry",
			expiry: time.Now().Add(1 * time.Hour),
			want:   true,
		},
		{
			name:   "no expiry (zero value)",
			expiry: time.Time{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &ParsedCredential{Expiry: tt.expiry}
			if got := pc.HasExpiry(); got != tt.want {
				t.Errorf("HasExpiry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsedCredential_VCTypes(t *testing.T) {
	tests := []struct {
		name     string
		vcClaims map[string]interface{}
		want     []string
	}{
		{
			name: "single type",
			vcClaims: map[string]interface{}{
				VCClaimType: []interface{}{"VerifiableCredential"},
			},
			want: []string{"VerifiableCredential"},
		},
		{
			name: "multiple types",
			vcClaims: map[string]interface{}{
				VCClaimType: []interface{}{"VerifiableCredential", "UniversityDegreeCredential"},
			},
			want: []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
		{
			name:     "nil vc claims",
			vcClaims: nil,
			want:     nil,
		},
		{
			name:     "vc claims without type",
			vcClaims: map[string]interface{}{"other": "value"},
			want:     nil,
		},
		{
			name: "vc claims with non-array type",
			vcClaims: map[string]interface{}{
				VCClaimType: "not-an-array",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &ParsedCredential{VCClaims: tt.vcClaims}
			got := pc.VCTypes()
			if tt.want == nil {
				if got != nil {
					t.Errorf("VCTypes() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("VCTypes() length = %d, want %d", len(got), len(tt.want))
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("VCTypes()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestParseJWTCredential_RawJWTPreserved(t *testing.T) {
	jwt := buildJWT(
		map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{ClaimIss: "test"},
	)

	parsed, err := ParseJWTCredential(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.RawJWT != jwt {
		t.Errorf("RawJWT not preserved: got %q, want %q", parsed.RawJWT, jwt)
	}
}

func TestParseJWTCredential_HeaderParsed(t *testing.T) {
	jwt := buildJWT(
		map[string]interface{}{"alg": "ES256", "typ": "JWT", "kid": "key-1"},
		map[string]interface{}{ClaimIss: "test"},
	)

	parsed, err := ParseJWTCredential(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.Header["alg"] != "ES256" {
		t.Errorf("Header[alg] = %v, want ES256", parsed.Header["alg"])
	}
	if parsed.Header["kid"] != "key-1" {
		t.Errorf("Header[kid] = %v, want key-1", parsed.Header["kid"])
	}
}

func TestParseJWTCredential_AllClaimsAccessible(t *testing.T) {
	jwt := buildJWT(
		map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{
			ClaimIss:       "test-issuer",
			"custom_claim": "custom_value",
		},
	)

	parsed, err := ParseJWTCredential(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.AllClaims["custom_claim"] != "custom_value" {
		t.Errorf("AllClaims[custom_claim] = %v, want custom_value", parsed.AllClaims["custom_claim"])
	}
}

func TestExtractTimeClaim_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]interface{}
		key    string
		isZero bool
	}{
		{
			name:   "missing claim",
			claims: map[string]interface{}{},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "zero timestamp",
			claims: map[string]interface{}{ClaimExp: float64(0)},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "negative timestamp",
			claims: map[string]interface{}{ClaimExp: float64(-1)},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "string instead of number",
			claims: map[string]interface{}{ClaimExp: "not-a-number"},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "valid timestamp",
			claims: map[string]interface{}{ClaimExp: float64(1700000000)},
			key:    ClaimExp,
			isZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTimeClaim(tt.claims, tt.key)
			if tt.isZero && !result.IsZero() {
				t.Errorf("expected zero time, got %v", result)
			}
			if !tt.isZero && result.IsZero() {
				t.Errorf("expected non-zero time, got zero")
			}
		})
	}
}
