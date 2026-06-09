package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// maxOfferResponseBytes is the maximum size of a credential offer response body.
const maxOfferResponseBytes = 1 << 20 // 1 MiB

// CreateCredentialOffer requests a pre-authorized credential offer from the issuer's
// create-credential-offer endpoint. The issuer must support the OID4VCI credential
// offer REST API with pre-authorized code grants.
//
// The accessToken must be a valid bearer token obtained via client_credentials grant
// from the same issuer. The credential offer is created for the service account
// associated with the client.
func (c *oid4vciClient) CreateCredentialOffer(
	ctx context.Context,
	issuerURL, accessToken, credentialConfigID string,
) (*CredentialOfferURI, error) {
	logger := log.FromContext(ctx).WithName("oid4vci")

	offerURL := strings.TrimRight(issuerURL, "/") + CredentialOfferCreatePath

	params := url.Values{}
	params.Set("credential_configuration_id", credentialConfigID)
	params.Set("pre_authorized", "true")
	fullURL := offerURL + "?" + params.Encode()

	logger.V(1).Info("Creating credential offer", "url", offerURL, "credentialConfigID", credentialConfigID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		logger.Error(err, "Failed to create credential offer request", "url", offerURL)
		return nil, fmt.Errorf("%w: %v", ErrCredentialOffer, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Error(err, "Failed to execute credential offer request", "url", offerURL)
		return nil, fmt.Errorf("%w: %v", ErrCredentialOffer, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		httpErr := parseHTTPError(resp)
		logger.Error(httpErr, "Credential offer endpoint returned non-OK status",
			"url", offerURL, "statusCode", resp.StatusCode)
		return nil, fmt.Errorf("%w: %v", ErrCredentialOffer, httpErr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOfferResponseBytes))
	if err != nil {
		logger.Error(err, "Failed to read credential offer response body", "url", offerURL)
		return nil, fmt.Errorf("%w: error reading response body: %v", ErrCredentialOffer, err)
	}

	logger.V(1).Info("Received credential offer response",
		"statusCode", resp.StatusCode,
		"body", string(body),
	)

	var offerURI CredentialOfferURI
	if err := json.Unmarshal(body, &offerURI); err != nil {
		logger.Error(err, "Failed to parse credential offer URI response", "url", offerURL)
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if offerURI.Nonce == "" {
		return nil, fmt.Errorf("%w: credential offer response missing nonce", ErrCredentialOffer)
	}

	logger.Info("Successfully created credential offer",
		"nonce", offerURI.Nonce,
		"credentialConfigID", credentialConfigID,
	)

	return &offerURI, nil
}

// FetchCredentialOffer retrieves the full credential offer using the nonce from
// a previously created offer. The offer is fetched from the issuer's credential-offer
// endpoint, which is unauthenticated.
//
// The issuerURL is used to construct the internal retrieval URL rather than using
// the external URL from the CredentialOfferURI response, ensuring the request
// stays within the cluster network.
func (c *oid4vciClient) FetchCredentialOffer(
	ctx context.Context,
	issuerURL, nonce string,
) (*CredentialOffer, error) {
	logger := log.FromContext(ctx).WithName("oid4vci")

	offerURL := strings.TrimRight(issuerURL, "/") + CredentialOfferBasePath + "/" + nonce

	logger.V(1).Info("Fetching credential offer", "url", offerURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, offerURL, nil)
	if err != nil {
		logger.Error(err, "Failed to create credential offer fetch request", "url", offerURL)
		return nil, fmt.Errorf("%w: %v", ErrCredentialOffer, err)
	}
	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Error(err, "Failed to fetch credential offer", "url", offerURL)
		return nil, fmt.Errorf("%w: %v", ErrCredentialOffer, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		httpErr := parseHTTPError(resp)
		logger.Error(httpErr, "Credential offer fetch returned non-OK status",
			"url", offerURL, "statusCode", resp.StatusCode)
		return nil, fmt.Errorf("%w: %v", ErrCredentialOffer, httpErr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOfferResponseBytes))
	if err != nil {
		logger.Error(err, "Failed to read credential offer body", "url", offerURL)
		return nil, fmt.Errorf("%w: error reading response body: %v", ErrCredentialOffer, err)
	}

	logger.V(1).Info("Received credential offer",
		"statusCode", resp.StatusCode,
		"body", string(body),
	)

	var offer CredentialOffer
	if err := json.Unmarshal(body, &offer); err != nil {
		logger.Error(err, "Failed to parse credential offer JSON", "url", offerURL)
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	logger.Info("Successfully fetched credential offer",
		"credentialIssuer", offer.CredentialIssuer,
		"credentialConfigs", offer.CredentialConfigurationIDs,
	)

	return &offer, nil
}
