// Package oid4vci implements an OID4VCI (OpenID for Verifiable Credential Issuance)
// protocol client. It handles metadata discovery, token acquisition via OAuth 2.0
// grants, and credential issuance requests including proof-of-possession JWT generation.
package oid4vci

import (
	"fmt"
	"time"
)

// Well-known discovery and protocol constants.
const (
	// WellKnownPath is the well-known path appended to an issuer URL
	// for OID4VCI credential issuer metadata discovery.
	WellKnownPath = "/.well-known/openid-credential-issuer"

	// DefaultHTTPTimeout is the default timeout for HTTP requests to OID4VCI endpoints.
	DefaultHTTPTimeout = 30 * time.Second

	// ProofTypeJWT identifies the JWT proof type used in credential requests.
	ProofTypeJWT = "jwt"

	// ProofAlgorithmES256 is the ECDSA P-256 signing algorithm for proof-of-possession JWTs.
	ProofAlgorithmES256 = "ES256"

	// JWTProofHeaderType is the JWT header "typ" value for OID4VCI proof-of-possession tokens.
	JWTProofHeaderType = "openid4vci-proof+jwt"

	// ContentTypeJSON is the MIME type for JSON request/response bodies.
	ContentTypeJSON = "application/json"

	// ECDSAKeySize is the bit size of the ECDSA P-256 curve used for key generation.
	ECDSAKeySize = 256
)

// GrantType represents an OAuth 2.0 grant type used for token acquisition.
type GrantType string

const (
	// GrantTypeClientCredentials is the OAuth 2.0 client_credentials grant type,
	// used for service-to-service authentication.
	GrantTypeClientCredentials GrantType = "client_credentials"

	// GrantTypePreAuthorizedCode is the OID4VCI pre-authorized_code grant type,
	// used when the issuer provides a pre-authorized code out-of-band.
	GrantTypePreAuthorizedCode GrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// IssuerMetadata represents the OID4VCI credential issuer metadata
// fetched from {issuerURL}/.well-known/openid-credential-issuer.
// See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
type IssuerMetadata struct {
	// CredentialIssuer is the unique identifier of the credential issuer.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialEndpoint is the URL of the credential issuance endpoint.
	CredentialEndpoint string `json:"credential_endpoint"`

	// TokenEndpoint is the URL of the token endpoint.
	// May be empty if the authorization_server field is used instead.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// AuthorizationServer is the URL of the OAuth 2.0 authorization server,
	// if different from the credential issuer.
	AuthorizationServer string `json:"authorization_server,omitempty"`

	// NonceEndpoint is the URL of the nonce endpoint (OID4VCI draft 15+/Keycloak 26.x).
	// When present, clients must obtain a nonce from this endpoint for proof JWTs
	// instead of relying on c_nonce from the token response.
	NonceEndpoint string `json:"nonce_endpoint,omitempty"`

	// CredentialConfigurationsSupported maps credential configuration IDs
	// to their supported configuration details.
	CredentialConfigurationsSupported map[string]CredentialConfiguration `json:"credential_configurations_supported"`
}

// CredentialConfiguration describes a credential type supported by the issuer,
// including its format, cryptographic requirements, and optional definition.
type CredentialConfiguration struct {
	// Format is the credential format identifier (e.g., "jwt_vc_json", "ldp_vc").
	Format string `json:"format"`

	// Scope is the OAuth 2.0 scope associated with this credential configuration.
	Scope string `json:"scope,omitempty"`

	// CryptographicBindingMethodsSupported lists the key binding methods
	// the issuer accepts for this credential type.
	CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported,omitempty"`

	// ProofTypesSupported maps proof type identifiers to their configuration,
	// describing what proof mechanisms the issuer accepts.
	ProofTypesSupported map[string]ProofTypeConfig `json:"proof_types_supported,omitempty"`

	// CredentialDefinition contains type and context information for the credential.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
}

// ProofTypeConfig describes the configuration for a supported proof type,
// including which signing algorithms are accepted.
type ProofTypeConfig struct {
	// ProofSigningAlgValuesSupported lists the cryptographic algorithms
	// the issuer accepts for this proof type.
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported,omitempty"`
}

// CredentialDefinition contains the type and JSON-LD context information
// for a verifiable credential.
type CredentialDefinition struct {
	// Type lists the credential type URIs (e.g., "VerifiableCredential", "UniversityDegreeCredential").
	Type []string `json:"type,omitempty"`

	// Context lists the JSON-LD context URIs.
	Context []string `json:"@context,omitempty"`
}

// TokenAuth contains authentication parameters for acquiring an access token
// from the token endpoint. The GrantType field determines which other fields
// are relevant.
type TokenAuth struct {
	// GrantType specifies the OAuth 2.0 grant type to use.
	GrantType GrantType

	// ClientID is the OAuth 2.0 client identifier.
	// Required for GrantTypeClientCredentials.
	ClientID string

	// ClientSecret is the OAuth 2.0 client secret.
	// Required for GrantTypeClientCredentials.
	ClientSecret string

	// PreAuthorizedCode is the pre-authorized code provided by the issuer.
	// Required for GrantTypePreAuthorizedCode.
	PreAuthorizedCode string

	// Scopes lists the OAuth 2.0 scopes to request.
	Scopes []string
}

// TokenResponse contains the parsed response from the token endpoint,
// including the access token and optional nonce for credential requests.
type TokenResponse struct {
	// AccessToken is the issued OAuth 2.0 access token.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token issued (typically "Bearer").
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds of the access token.
	ExpiresIn int `json:"expires_in,omitempty"`

	// CNonce is the nonce value to include in proof-of-possession JWTs
	// when requesting credentials.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn is the lifetime in seconds of the c_nonce value.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`

	// Scope is the scope of the access token, if different from requested.
	Scope string `json:"scope,omitempty"`

	// AuthorizationDetails contains the RFC 9396 authorization details from the token response.
	// When present with credential_identifiers, the credential request must use
	// credential_identifier instead of credential_configuration_id + format.
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
}

// AuthorizationDetail represents a single entry in the RFC 9396 authorization_details
// array returned in a token response from an OID4VCI issuer.
type AuthorizationDetail struct {
	// Type is the authorization detail type (e.g., "openid_credential").
	Type string `json:"type"`

	// CredentialConfigurationID identifies the credential configuration this detail applies to.
	CredentialConfigurationID string `json:"credential_configuration_id,omitempty"`

	// CredentialIdentifiers lists the specific credential identifiers that must be used
	// in credential requests instead of credential_configuration_id + format.
	CredentialIdentifiers []string `json:"credential_identifiers,omitempty"`
}

// CredentialIdentifierForConfig returns the first credential_identifier from authorization_details
// matching the given credential configuration ID. Returns empty string if no match is found.
func (r *TokenResponse) CredentialIdentifierForConfig(credentialConfigID string) string {
	for _, ad := range r.AuthorizationDetails {
		if ad.CredentialConfigurationID == credentialConfigID && len(ad.CredentialIdentifiers) > 0 {
			return ad.CredentialIdentifiers[0]
		}
	}
	return ""
}

// CredentialRequest represents a request to the credential issuance endpoint.
// It specifies which credential to issue and provides proof of key possession.
// When CredentialIdentifier is set, it takes precedence over CredentialConfigurationID
// and Format per OID4VCI spec section 7.2.
//
// Supports both the draft 13 "proof" (singular) format and the draft 14+ "proofs"
// (plural) format. Set Proofs for issuers implementing draft 14+ (e.g., Keycloak 26.x)
// and Proof for legacy issuers.
type CredentialRequest struct {
	// CredentialConfigurationID identifies the requested credential configuration
	// as advertised in the issuer's metadata. Omitted when CredentialIdentifier is used.
	CredentialConfigurationID string `json:"credential_configuration_id,omitempty"`

	// CredentialIdentifier is a specific credential identifier from the authorization_details
	// in the token response. When present, CredentialConfigurationID and Format are omitted.
	CredentialIdentifier string `json:"credential_identifier,omitempty"`

	// Format specifies the desired credential format (e.g., "jwt_vc_json").
	Format string `json:"format,omitempty"`

	// Proof contains the proof of possession of cryptographic key material
	// in the draft <=13 singular format.
	Proof *CredentialProof `json:"proof,omitempty"`

	// Proofs contains proof(s) of possession in the draft 14+ plural format.
	// Keyed by proof type (e.g., "jwt"), with values as arrays of proof strings.
	Proofs map[string][]string `json:"proofs,omitempty"`

	// CredentialDefinition optionally specifies additional credential type information.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
}

// CredentialProof contains a proof of possession for a credential request
// in the OID4VCI draft <=13 singular format.
type CredentialProof struct {
	// ProofType is the type of proof (e.g., "jwt").
	ProofType string `json:"proof_type"`

	// JWT is the compact-serialized JWT proof of possession.
	// Used when ProofType is "jwt".
	JWT string `json:"jwt,omitempty"`
}

// CredentialResponse contains the parsed response from the credential endpoint,
// including the issued credential and optional updated nonce.
// Supports both the singular "credential" field (OID4VCI draft ≤13) and the
// plural "credentials" array (OID4VCI draft 14+/Keycloak 26.x).
type CredentialResponse struct {
	// Credential is the issued verifiable credential (singular format).
	// Its type depends on the format: a string for JWT-based formats,
	// or a JSON object for JSON-LD formats.
	Credential any `json:"credential,omitempty"`

	// Credentials is the issued credentials array (plural format, OID4VCI draft 14+).
	// Each entry wraps a credential value.
	Credentials []CredentialEntry `json:"credentials,omitempty"`

	// Format is the format of the issued credential.
	Format string `json:"format,omitempty"`

	// CNonce is an updated nonce for subsequent credential requests.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn is the lifetime in seconds of the updated c_nonce.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`
}

// CredentialEntry represents a single entry in the "credentials" array
// returned by the credential endpoint in OID4VCI draft 14+ responses.
type CredentialEntry struct {
	// Credential is the issued verifiable credential value.
	Credential any `json:"credential"`
}

// CredentialAsString returns the credential as a string.
// It checks the singular "credential" field first, then falls back to the
// first entry in the "credentials" array. Returns empty string if neither
// contains a string credential.
func (r *CredentialResponse) CredentialAsString() string {
	if s, ok := r.Credential.(string); ok {
		return s
	}
	if len(r.Credentials) > 0 {
		if s, ok := r.Credentials[0].Credential.(string); ok {
			return s
		}
	}
	return ""
}

// OID4VCI protocol path constants for credential offer endpoints.
const (
	// CredentialOfferCreatePath is the path appended to an issuer URL
	// for creating a credential offer.
	CredentialOfferCreatePath = "/protocol/oid4vc/create-credential-offer"

	// CredentialOfferBasePath is the path prefix appended to an issuer URL
	// for retrieving a credential offer by nonce.
	CredentialOfferBasePath = "/protocol/oid4vc/credential-offer"
)

// CredentialOfferURI is the response from the create-credential-offer endpoint.
// It contains the offer endpoint and a nonce used to retrieve the full offer.
type CredentialOfferURI struct {
	// Issuer is the credential offer endpoint URL.
	Issuer string `json:"issuer"`

	// Nonce is the lookup key for retrieving the full credential offer.
	Nonce string `json:"nonce"`
}

// CredentialOffer is the full credential offer retrieved via the offer nonce.
// It contains the issuer identity, available credential configurations, and
// grant details including the pre-authorized code.
type CredentialOffer struct {
	// CredentialIssuer is the identifier of the credential issuer.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialConfigurationIDs lists the credential configurations available in this offer.
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`

	// Grants maps grant type URIs to their parameters.
	Grants map[string]PreAuthorizedGrant `json:"grants"`
}

// PreAuthorizedCode extracts the pre-authorized code from the credential offer's grants.
// Returns an error if the offer does not contain a pre-authorized code grant.
func (o *CredentialOffer) PreAuthorizedCode() (string, error) {
	grant, ok := o.Grants[string(GrantTypePreAuthorizedCode)]
	if !ok {
		return "", fmt.Errorf("credential offer does not contain a pre-authorized code grant")
	}
	if grant.Code == "" {
		return "", fmt.Errorf("credential offer pre-authorized code grant has an empty code")
	}
	return grant.Code, nil
}

// PreAuthorizedGrant contains the pre-authorized code from a credential offer.
type PreAuthorizedGrant struct {
	// Code is the pre-authorized code to exchange for an access token.
	Code string `json:"pre-authorized_code"`

	// TxCode is an optional transaction code required alongside the pre-authorized code.
	TxCode string `json:"tx_code,omitempty"`

	// AuthorizationServer is the optional authorization server URL, if different from the issuer.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// OIDCError represents an error response from an OID4VCI or OAuth 2.0 endpoint.
type OIDCError struct {
	// ErrorCode is the OAuth 2.0 error code (e.g., "invalid_request", "invalid_grant").
	ErrorCode string `json:"error"`

	// ErrorDescription is a human-readable description of the error.
	ErrorDescription string `json:"error_description,omitempty"`
}

// Error implements the error interface for OIDCError.
func (e *OIDCError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}
