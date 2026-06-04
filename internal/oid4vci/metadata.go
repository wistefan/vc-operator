package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxMetadataResponseBytes is the maximum size of a metadata response body
// to prevent excessive memory allocation from malicious or buggy servers.
const maxMetadataResponseBytes = 1 << 20 // 1 MiB

// DiscoverMetadata fetches and parses the OID4VCI credential issuer metadata
// from the well-known endpoint at {issuerURL}/.well-known/openid-credential-issuer.
//
// The issuerURL should be the base URL of the credential issuer without a trailing slash.
// The method returns the parsed metadata or an error if the request fails or the
// response cannot be parsed.
func (c *oid4vciClient) DiscoverMetadata(ctx context.Context, issuerURL string) (*IssuerMetadata, error) {
	metadataURL := strings.TrimRight(issuerURL, "/") + WellKnownPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataFetch, err)
	}
	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %v", ErrMetadataFetch, parseHTTPError(resp))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: error reading response body: %v", ErrMetadataFetch, err)
	}

	var metadata IssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	return &metadata, nil
}

// parseHTTPError reads the response body and attempts to parse it as an OIDCError.
// If parsing fails, it returns an HTTPError with just the status code.
func parseHTTPError(resp *http.Response) *HTTPError {
	httpErr := &HTTPError{
		StatusCode: resp.StatusCode,
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataResponseBytes))
	if err != nil {
		return httpErr
	}

	var oidcErr OIDCError
	if json.Unmarshal(body, &oidcErr) == nil && oidcErr.ErrorCode != "" {
		httpErr.OIDCErr = &oidcErr
	}

	return httpErr
}
