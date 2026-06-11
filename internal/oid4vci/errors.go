package oid4vci

import (
	"errors"
	"fmt"
)

// Sentinel errors for OID4VCI client operations.
var (
	// ErrMetadataFetch indicates a failure to fetch issuer metadata.
	ErrMetadataFetch = errors.New("failed to fetch issuer metadata")

	// ErrTokenAcquisition indicates a failure to obtain an access token.
	ErrTokenAcquisition = errors.New("failed to obtain access token")

	// ErrCredentialRequest indicates a failure to request a credential.
	ErrCredentialRequest = errors.New("failed to request credential")

	// ErrInvalidResponse indicates the server returned an unparseable response.
	ErrInvalidResponse = errors.New("invalid response from server")

	// ErrKeyGeneration indicates a failure to generate a cryptographic key pair.
	ErrKeyGeneration = errors.New("failed to generate key pair")

	// ErrProofGeneration indicates a failure to generate a proof-of-possession JWT.
	ErrProofGeneration = errors.New("failed to generate proof of possession")

	// ErrUnsupportedGrantType indicates an unsupported OAuth grant type was specified.
	ErrUnsupportedGrantType = errors.New("unsupported grant type")

	// ErrCredentialOffer indicates a failure to create or fetch a credential offer.
	ErrCredentialOffer = errors.New("failed to create or fetch credential offer")
)

// HTTPError represents an HTTP-level error from an OID4VCI endpoint,
// capturing both the status code and any parsed error body.
type HTTPError struct {
	// StatusCode is the HTTP response status code.
	StatusCode int

	// OIDCErr is the parsed OIDC error response, if available.
	OIDCErr *OIDCError
}

// Error implements the error interface for HTTPError.
func (e *HTTPError) Error() string {
	if e.OIDCErr != nil {
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.OIDCErr.Error())
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// Unwrap returns the underlying OIDCError if present, allowing errors.Is/As
// to match the inner error.
func (e *HTTPError) Unwrap() error {
	if e.OIDCErr != nil {
		return e.OIDCErr
	}
	return nil
}
