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

import "time"

// RenewalInfo contains computed renewal scheduling information for a credential.
type RenewalInfo struct {
	// ExpiryTime is the credential's expiry time. Zero value means the
	// credential does not have an explicit expiry.
	ExpiryTime time.Time

	// RenewalTime is the computed time at which renewal should be triggered.
	// This is typically ExpiryTime - RenewBefore.
	RenewalTime time.Time

	// TimeUntilRenewal is the duration from the reference time until renewal
	// should be triggered. Negative values indicate renewal is overdue.
	TimeUntilRenewal time.Duration

	// IsExpired is true if the credential has already expired relative to
	// the reference time used for computation.
	IsExpired bool

	// NeedsRenewal is true if renewal should be triggered immediately,
	// either because the credential is already expired or the renewal
	// window has been reached.
	NeedsRenewal bool

	// UsedDefaultTTL is true if the credential had no explicit expiry and
	// the default TTL was applied to compute renewal.
	UsedDefaultTTL bool
}

// ComputeRenewalInfo calculates when a credential should be renewed based on
// its expiry time, the desired renewal buffer (renewBefore), and the current
// reference time.
//
// If the credential has no explicit expiry (pc.Expiry is zero), the
// DefaultCredentialTTL is applied from the issued-at time (or from 'now'
// if issued-at is also absent) to derive a synthetic expiry.
//
// The renewBefore parameter specifies how long before expiry the renewal
// should be triggered. If renewBefore is zero, DefaultRenewBeforeDuration
// is used. The resulting time-until-renewal is clamped to at least
// MinRenewalInterval to prevent tight renewal loops.
func ComputeRenewalInfo(pc *ParsedCredential, renewBefore time.Duration, now time.Time) *RenewalInfo {
	if renewBefore <= 0 {
		renewBefore = DefaultRenewBeforeDuration
	}

	info := &RenewalInfo{}

	// Determine the effective expiry time.
	if pc.HasExpiry() {
		info.ExpiryTime = pc.Expiry
	} else {
		// No explicit expiry: compute a synthetic one using the default TTL.
		info.UsedDefaultTTL = true
		baseTime := pc.IssuedAt
		if baseTime.IsZero() {
			baseTime = now
		}
		info.ExpiryTime = baseTime.Add(DefaultCredentialTTL)
	}

	// Cap the expiry to MaxCredentialLifetime from now.
	maxExpiry := now.Add(MaxCredentialLifetime)
	if info.ExpiryTime.After(maxExpiry) {
		info.ExpiryTime = maxExpiry
	}

	// Check if already expired.
	info.IsExpired = now.After(info.ExpiryTime) || now.Equal(info.ExpiryTime)

	// Compute renewal time.
	info.RenewalTime = info.ExpiryTime.Add(-renewBefore)

	// Compute time until renewal.
	info.TimeUntilRenewal = info.RenewalTime.Sub(now)

	// Determine if renewal is needed now.
	info.NeedsRenewal = info.IsExpired || info.TimeUntilRenewal <= 0

	// Clamp the time-until-renewal to at least MinRenewalInterval
	// to prevent tight loops, but only if renewal is not needed now.
	if !info.NeedsRenewal && info.TimeUntilRenewal < MinRenewalInterval {
		info.TimeUntilRenewal = MinRenewalInterval
	}

	return info
}

// TimeUntilExpiry returns the duration until the credential expires relative
// to the given reference time. If the credential has no expiry, it returns
// the DefaultCredentialTTL. A negative duration means the credential has
// already expired.
func TimeUntilExpiry(pc *ParsedCredential, now time.Time) time.Duration {
	if !pc.HasExpiry() {
		return DefaultCredentialTTL
	}
	return pc.Expiry.Sub(now)
}
