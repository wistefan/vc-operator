package oid4vci

import (
	"context"
	"net/http"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Client defines the high-level interface for interacting with an OID4VCI
// credential issuer. It supports metadata discovery, token acquisition,
// and credential issuance requests.
type Client interface {
	// DiscoverMetadata fetches and parses the OID4VCI credential issuer metadata
	// from the well-known endpoint at {issuerURL}/.well-known/openid-credential-issuer.
	DiscoverMetadata(ctx context.Context, issuerURL string) (*IssuerMetadata, error)

	// ObtainAccessToken requests an OAuth 2.0 access token from the given token endpoint
	// using the specified authentication parameters (client credentials or pre-authorized code).
	ObtainAccessToken(ctx context.Context, tokenURL string, auth TokenAuth) (*TokenResponse, error)

	// RequestCredential sends a credential issuance request to the given credential endpoint,
	// authenticated with the provided access token, and returns the issued credential.
	RequestCredential(ctx context.Context, credentialURL string, accessToken string, request CredentialRequest) (*CredentialResponse, error)

	// CreateCredentialOffer requests a pre-authorized credential offer from the issuer.
	// The issuerURL is the base issuer URL (e.g., http://keycloak:8080/realms/my-realm).
	// The accessToken must be a valid bearer token with permission to create offers.
	CreateCredentialOffer(ctx context.Context, issuerURL, accessToken, credentialConfigID string) (*CredentialOfferURI, error)

	// FetchCredentialOffer retrieves the full credential offer using the nonce
	// obtained from CreateCredentialOffer. The issuerURL is used to construct
	// the internal offer retrieval URL.
	FetchCredentialOffer(ctx context.Context, issuerURL, nonce string) (*CredentialOffer, error)

	// FetchNonce obtains a fresh c_nonce from the issuer's nonce endpoint
	// (OID4VCI draft 15+/Keycloak 26.x). The returned nonce is used in
	// proof-of-possession JWTs when the token response does not include one.
	FetchNonce(ctx context.Context, nonceEndpoint, accessToken string) (string, error)
}

// ClientOption is a functional option for configuring an oid4vciClient.
type ClientOption func(*oid4vciClient)

// WithHTTPClient sets a custom http.Client for the OID4VCI client.
// This is primarily useful for testing with mock HTTP servers.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *oid4vciClient) {
		c.httpClient = httpClient
	}
}

// WithTimeout sets the HTTP request timeout for the OID4VCI client.
// If not specified, DefaultHTTPTimeout is used.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *oid4vciClient) {
		c.httpClient.Timeout = timeout
	}
}

// packageLogger is a package-level logger for standalone functions without context.
var packageLogger = logf.Log.WithName("oid4vci")

// NewClient creates a new OID4VCI client with the given options.
// If no http.Client is provided via WithHTTPClient, a default client
// with DefaultHTTPTimeout is used.
func NewClient(opts ...ClientOption) Client {
	c := &oid4vciClient{
		httpClient: &http.Client{
			Timeout: DefaultHTTPTimeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	packageLogger.V(1).Info("OID4VCI client created", "timeout", c.httpClient.Timeout)
	return c
}

// oid4vciClient is the default implementation of the Client interface.
// It uses an http.Client for all HTTP communication with OID4VCI endpoints.
type oid4vciClient struct {
	httpClient *http.Client
}
