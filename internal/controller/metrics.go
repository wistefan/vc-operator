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

package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Metric namespace and subsystem constants for Prometheus metrics.
const (
	// MetricsNamespace is the Prometheus namespace for all vc-operator metrics.
	MetricsNamespace = "vc_operator"

	// MetricsLabelNamespace is the Prometheus label for the Kubernetes namespace
	// of the VerifiableCredentialRequest.
	MetricsLabelNamespace = "namespace"

	// MetricsLabelName is the Prometheus label for the name of the
	// VerifiableCredentialRequest.
	MetricsLabelName = "name"

	// MetricsLabelCredentialType is the Prometheus label for the credential type.
	MetricsLabelCredentialType = "credential_type"

	// MetricsLabelReason is the Prometheus label for the error reason.
	MetricsLabelReason = "reason"
)

// VCRequestMetrics holds Prometheus metric collectors for the
// VerifiableCredentialRequest controller. These metrics track credential
// issuance, renewal, errors, and expiry status.
type VCRequestMetrics struct {
	// CredentialsIssuedTotal counts the total number of credentials
	// successfully issued (initial issuance only).
	CredentialsIssuedTotal *prometheus.CounterVec

	// CredentialsRenewedTotal counts the total number of credentials
	// successfully renewed.
	CredentialsRenewedTotal *prometheus.CounterVec

	// CredentialsErrorsTotal counts the total number of credential
	// acquisition errors by reason.
	CredentialsErrorsTotal *prometheus.CounterVec

	// CredentialExpirySeconds is a gauge reporting the Unix timestamp
	// (in seconds) at which the current credential expires. This allows
	// Prometheus alerting rules like:
	//   vc_operator_credential_expiry_seconds - time() < 300
	CredentialExpirySeconds *prometheus.GaugeVec
}

// NewVCRequestMetrics creates and returns a new VCRequestMetrics instance
// with all Prometheus collectors initialized.
func NewVCRequestMetrics() *VCRequestMetrics {
	return &VCRequestMetrics{
		CredentialsIssuedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: MetricsNamespace,
				Name:      "credentials_issued_total",
				Help:      "Total number of credentials successfully issued (initial issuance).",
			},
			[]string{MetricsLabelNamespace, MetricsLabelName, MetricsLabelCredentialType},
		),
		CredentialsRenewedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: MetricsNamespace,
				Name:      "credentials_renewed_total",
				Help:      "Total number of credentials successfully renewed.",
			},
			[]string{MetricsLabelNamespace, MetricsLabelName, MetricsLabelCredentialType},
		),
		CredentialsErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: MetricsNamespace,
				Name:      "credentials_errors_total",
				Help:      "Total number of credential acquisition errors by reason.",
			},
			[]string{MetricsLabelNamespace, MetricsLabelName, MetricsLabelReason},
		),
		CredentialExpirySeconds: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: MetricsNamespace,
				Name:      "credential_expiry_seconds",
				Help:      "Unix timestamp (in seconds) at which the current credential expires.",
			},
			[]string{MetricsLabelNamespace, MetricsLabelName, MetricsLabelCredentialType},
		),
	}
}

// RegisterMetrics registers all VCRequest Prometheus metrics with the
// controller-runtime metrics registry. This must be called during
// controller setup, before the manager starts serving metrics.
func RegisterMetrics(m *VCRequestMetrics) {
	metrics.Registry.MustRegister(
		m.CredentialsIssuedTotal,
		m.CredentialsRenewedTotal,
		m.CredentialsErrorsTotal,
		m.CredentialExpirySeconds,
	)
}
