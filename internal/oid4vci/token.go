package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxTokenResponseBytes is the maximum size of a token response body
// to prevent excessive memory allocation.
const maxTokenResponseBytes = 1 << 20 // 1 MiB

// Token request form field names as per OAuth 2.0 and OID4VCI specifications.
const (
	// FormFieldGrantType is the form field for the OAuth grant type.
	FormFieldGrantType = "grant_type"

	// FormFieldClientID is the form field for the OAuth client identifier.
	FormFieldClientID = "client_id"

	// FormFieldClientSecret is the form field for the OAuth client secret.
	FormFieldClientSecret = "client_secret"

	// FormFieldScope is the form field for the requested OAuth scopes.
	FormFieldScope = "scope"

	// FormFieldPreAuthorizedCode is the form field for the OID4VCI pre-authorized code.
	FormFieldPreAuthorizedCode = "pre-authorized_code"
)

// ContentTypeFormURLEncoded is the MIME type for URL-encoded form data.
const ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"

// ObtainAccessToken requests an OAuth 2.0 access token from the given token endpoint.
// It supports both client_credentials and pre-authorized_code grant types.
//
// For client_credentials: auth.ClientID and auth.ClientSecret must be provided.
// For pre-authorized_code: auth.PreAuthorizedCode must be provided.
//
// Returns the parsed token response including the access token and optional c_nonce,
// or an error if the request fails.
func (c *oid4vciClient) ObtainAccessToken(ctx context.Context, tokenURL string, auth TokenAuth) (*TokenResponse, error) {
	formData, err := buildTokenFormData(auth)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenAcquisition, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenAcquisition, err)
	}
	req.Header.Set("Content-Type", ContentTypeFormURLEncoded)
	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenAcquisition, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %v", ErrTokenAcquisition, parseHTTPError(resp))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: error reading response body: %v", ErrTokenAcquisition, err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	return &tokenResp, nil
}

// buildTokenFormData constructs the URL-encoded form data for a token request
// based on the grant type and authentication parameters.
func buildTokenFormData(auth TokenAuth) (url.Values, error) {
	form := url.Values{}

	switch auth.GrantType {
	case GrantTypeClientCredentials:
		form.Set(FormFieldGrantType, string(GrantTypeClientCredentials))
		form.Set(FormFieldClientID, auth.ClientID)
		form.Set(FormFieldClientSecret, auth.ClientSecret)

	case GrantTypePreAuthorizedCode:
		form.Set(FormFieldGrantType, string(GrantTypePreAuthorizedCode))
		form.Set(FormFieldPreAuthorizedCode, auth.PreAuthorizedCode)
		if auth.ClientID != "" {
			form.Set(FormFieldClientID, auth.ClientID)
		}

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedGrantType, auth.GrantType)
	}

	if len(auth.Scopes) > 0 {
		form.Set(FormFieldScope, strings.Join(auth.Scopes, " "))
	}

	return form, nil
}
