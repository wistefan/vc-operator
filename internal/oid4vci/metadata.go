package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/log"
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
	logger := log.FromContext(ctx).WithName("oid4vci")
	metadataURL := strings.TrimRight(issuerURL, "/") + WellKnownPath

	logger.V(1).Info("Discovering issuer metadata", "issuerURL", issuerURL, "metadataURL", metadataURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		logger.Error(err, "Failed to create metadata request", "metadataURL", metadataURL)
		return nil, fmt.Errorf("%w: %v", ErrMetadataFetch, err)
	}
	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Error(err, "Failed to fetch issuer metadata", "metadataURL", metadataURL)
		return nil, fmt.Errorf("%w: %v", ErrMetadataFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		httpErr := parseHTTPError(resp)
		logger.Error(httpErr, "Issuer metadata endpoint returned non-OK status", "metadataURL", metadataURL, "statusCode", resp.StatusCode)
		return nil, fmt.Errorf("%w: %v", ErrMetadataFetch, httpErr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataResponseBytes))
	if err != nil {
		logger.Error(err, "Failed to read metadata response body", "metadataURL", metadataURL)
		return nil, fmt.Errorf("%w: error reading response body: %v", ErrMetadataFetch, err)
	}

	var metadata IssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		logger.Error(err, "Failed to parse issuer metadata JSON", "metadataURL", metadataURL, "bodyLength", len(body))
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	logger.Info("Successfully discovered issuer metadata",
		"issuer", metadata.CredentialIssuer,
		"credentialEndpoint", metadata.CredentialEndpoint,
		"credentialConfigurations", len(metadata.CredentialConfigurationsSupported),
	)

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
