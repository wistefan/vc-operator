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
	"fmt"
	"strings"
	"time"
)

// ParsedCredential holds the extracted information from a parsed JWT
// Verifiable Credential, including standard JWT claims and VC-specific data.
type ParsedCredential struct {
	// RawJWT is the original compact-serialized JWT string.
	RawJWT string

	// Header contains the decoded JWT header claims (e.g., "alg", "typ", "kid").
	Header map[string]interface{}

	// Issuer is the value of the "iss" (Issuer) claim, identifying who
	// issued the credential.
	Issuer string

	// Subject is the value of the "sub" (Subject) claim, identifying the
	// entity the credential describes.
	Subject string

	// IssuedAt is the time extracted from the "iat" (Issued At) claim.
	// Zero value if the claim is absent.
	IssuedAt time.Time

	// Expiry is the time extracted from the "exp" (Expiration Time) claim.
	// Zero value if the claim is absent, meaning the credential does not expire.
	Expiry time.Time

	// NotBefore is the time extracted from the "nbf" (Not Before) claim.
	// Zero value if the claim is absent.
	NotBefore time.Time

	// JWTID is the value of the "jti" (JWT ID) claim, a unique identifier
	// for the JWT.
	JWTID string

	// VCClaims contains the decoded "vc" claim payload, which holds
	// VC-specific data such as type, credentialSubject, and @context.
	// Nil if no "vc" claim is present.
	VCClaims map[string]interface{}

	// AllClaims contains all decoded payload claims for access to
	// non-standard or issuer-specific claims.
	AllClaims map[string]interface{}
}

// HasExpiry reports whether the parsed credential contains an explicit
// expiry time (the "exp" claim was present and valid).
func (pc *ParsedCredential) HasExpiry() bool {
	return !pc.Expiry.IsZero()
}

// IsExpired reports whether the credential has expired relative to the
// given reference time. Returns false if no expiry is set.
func (pc *ParsedCredential) IsExpired(now time.Time) bool {
	if !pc.HasExpiry() {
		return false
	}
	return now.After(pc.Expiry)
}

// VCTypes returns the credential type strings from the "vc.type" claim.
// Returns nil if the "vc" claim is absent or has no "type" field.
func (pc *ParsedCredential) VCTypes() []string {
	if pc.VCClaims == nil {
		return nil
	}
	typeVal, ok := pc.VCClaims[VCClaimType]
	if !ok {
		return nil
	}
	arr, ok := typeVal.([]interface{})
	if !ok {
		return nil
	}
	types := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			types = append(types, s)
		}
	}
	return types
}

// ParseJWTCredential parses a compact-serialized JWT Verifiable Credential
// and extracts standard claims and VC-specific data. It does NOT verify
// the JWT signature — the operator trusts the issuer; signature verification
// is the holder/verifier's responsibility.
//
// The JWT must have three dot-separated segments (header.payload.signature).
// Both header and payload are Base64url-decoded and parsed as JSON.
func ParseJWTCredential(rawJWT string) (*ParsedCredential, error) {
	rawJWT = strings.TrimSpace(rawJWT)
	if rawJWT == "" {
		return nil, fmt.Errorf("empty JWT string")
	}

	segments := strings.Split(rawJWT, ".")
	if len(segments) != JWTSegmentCount {
		return nil, fmt.Errorf("invalid JWT: expected %d segments, got %d", JWTSegmentCount, len(segments))
	}

	// Decode and parse header.
	header, err := decodeJWTSegment(segments[JWTHeaderSegment])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	// Decode and parse payload.
	payload, err := decodeJWTSegment(segments[JWTPayloadSegment])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	pc := &ParsedCredential{
		RawJWT:    rawJWT,
		Header:    header,
		AllClaims: payload,
	}

	// Extract standard claims.
	pc.Issuer = extractStringClaim(payload, ClaimIss)
	pc.Subject = extractStringClaim(payload, ClaimSub)
	pc.JWTID = extractStringClaim(payload, ClaimJti)
	pc.Expiry = extractTimeClaim(payload, ClaimExp)
	pc.IssuedAt = extractTimeClaim(payload, ClaimIat)
	pc.NotBefore = extractTimeClaim(payload, ClaimNbf)

	// Extract VC claims.
	if vcRaw, ok := payload[ClaimVC]; ok {
		if vcMap, ok := vcRaw.(map[string]interface{}); ok {
			pc.VCClaims = vcMap
		}
	}

	return pc, nil
}

// decodeJWTSegment decodes a Base64url-encoded JWT segment and parses it
// as a JSON object. It handles both padded and unpadded Base64url encoding.
func decodeJWTSegment(segment string) (map[string]interface{}, error) {
	// Base64url decode (JWT uses raw URL encoding without padding).
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		// Try with standard padding as a fallback.
		decoded, err = base64.URLEncoding.DecodeString(addBase64Padding(segment))
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	return claims, nil
}

// addBase64Padding adds standard Base64 padding characters to a Base64url
// string that may be missing padding.
func addBase64Padding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// extractStringClaim extracts a string value from a JWT claims map.
// Returns an empty string if the claim is absent or not a string.
func extractStringClaim(claims map[string]interface{}, key string) string {
	val, ok := claims[key]
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return s
}

// extractTimeClaim extracts a Unix timestamp from a JWT claims map and
// converts it to a time.Time. Handles both integer and floating-point
// representations of the timestamp. Returns zero time if the claim is
// absent or not a valid number.
func extractTimeClaim(claims map[string]interface{}, key string) time.Time {
	val, ok := claims[key]
	if !ok {
		return time.Time{}
	}
	// JSON numbers are decoded as float64 by encoding/json.
	switch v := val.(type) {
	case float64:
		if v <= 0 {
			return time.Time{}
		}
		return time.Unix(int64(v), 0)
	case json.Number:
		n, err := v.Int64()
		if err != nil || n <= 0 {
			return time.Time{}
		}
		return time.Unix(n, 0)
	default:
		return time.Time{}
	}
}
