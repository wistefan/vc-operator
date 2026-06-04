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
	"testing"
	"time"
)

func TestComputeRenewalInfo(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name             string
		expiry           time.Time
		issuedAt         time.Time
		renewBefore      time.Duration
		wantNeedsRenewal bool
		wantIsExpired    bool
		wantUsedDefault  bool
		wantRenewalTime  time.Time
	}{
		{
			name:             "credential with future expiry, not yet in renewal window",
			expiry:           now.Add(2 * time.Hour),
			issuedAt:         now.Add(-1 * time.Hour),
			renewBefore:      10 * time.Minute,
			wantNeedsRenewal: false,
			wantIsExpired:    false,
			wantUsedDefault:  false,
			wantRenewalTime:  now.Add(2*time.Hour - 10*time.Minute),
		},
		{
			name:             "credential in renewal window (expiry within renewBefore)",
			expiry:           now.Add(3 * time.Minute),
			issuedAt:         now.Add(-57 * time.Minute),
			renewBefore:      5 * time.Minute,
			wantNeedsRenewal: true,
			wantIsExpired:    false,
			wantUsedDefault:  false,
			wantRenewalTime:  now.Add(3*time.Minute - 5*time.Minute),
		},
		{
			name:             "already expired credential",
			expiry:           now.Add(-30 * time.Minute),
			issuedAt:         now.Add(-2 * time.Hour),
			renewBefore:      5 * time.Minute,
			wantNeedsRenewal: true,
			wantIsExpired:    true,
			wantUsedDefault:  false,
			wantRenewalTime:  now.Add(-30*time.Minute - 5*time.Minute),
		},
		{
			name:             "credential expiring exactly now",
			expiry:           now,
			issuedAt:         now.Add(-1 * time.Hour),
			renewBefore:      5 * time.Minute,
			wantNeedsRenewal: true,
			wantIsExpired:    true,
			wantUsedDefault:  false,
			wantRenewalTime:  now.Add(-5 * time.Minute),
		},
		{
			name:             "no expiry uses default TTL from issued-at time",
			expiry:           time.Time{}, // no expiry
			issuedAt:         now.Add(-1 * time.Hour),
			renewBefore:      5 * time.Minute,
			wantNeedsRenewal: false,
			wantIsExpired:    false,
			wantUsedDefault:  true,
			wantRenewalTime:  now.Add(-1*time.Hour + DefaultCredentialTTL - 5*time.Minute),
		},
		{
			name:             "no expiry and no issued-at uses default TTL from now",
			expiry:           time.Time{},
			issuedAt:         time.Time{},
			renewBefore:      5 * time.Minute,
			wantNeedsRenewal: false,
			wantIsExpired:    false,
			wantUsedDefault:  true,
			wantRenewalTime:  now.Add(DefaultCredentialTTL - 5*time.Minute),
		},
		{
			name:             "zero renewBefore uses default",
			expiry:           now.Add(1 * time.Hour),
			issuedAt:         now,
			renewBefore:      0,
			wantNeedsRenewal: false,
			wantIsExpired:    false,
			wantUsedDefault:  false,
			wantRenewalTime:  now.Add(1*time.Hour - DefaultRenewBeforeDuration),
		},
		{
			name:             "negative renewBefore uses default",
			expiry:           now.Add(1 * time.Hour),
			issuedAt:         now,
			renewBefore:      -10 * time.Minute,
			wantNeedsRenewal: false,
			wantIsExpired:    false,
			wantUsedDefault:  false,
			wantRenewalTime:  now.Add(1*time.Hour - DefaultRenewBeforeDuration),
		},
		{
			name:             "renewBefore larger than remaining lifetime triggers immediate renewal",
			expiry:           now.Add(2 * time.Minute),
			issuedAt:         now.Add(-58 * time.Minute),
			renewBefore:      30 * time.Minute,
			wantNeedsRenewal: true,
			wantIsExpired:    false,
			wantUsedDefault:  false,
			wantRenewalTime:  now.Add(2*time.Minute - 30*time.Minute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &ParsedCredential{
				Expiry:   tt.expiry,
				IssuedAt: tt.issuedAt,
			}

			info := ComputeRenewalInfo(pc, tt.renewBefore, now)

			if info.NeedsRenewal != tt.wantNeedsRenewal {
				t.Errorf("NeedsRenewal = %v, want %v", info.NeedsRenewal, tt.wantNeedsRenewal)
			}
			if info.IsExpired != tt.wantIsExpired {
				t.Errorf("IsExpired = %v, want %v", info.IsExpired, tt.wantIsExpired)
			}
			if info.UsedDefaultTTL != tt.wantUsedDefault {
				t.Errorf("UsedDefaultTTL = %v, want %v", info.UsedDefaultTTL, tt.wantUsedDefault)
			}
			if !info.RenewalTime.Equal(tt.wantRenewalTime) {
				t.Errorf("RenewalTime = %v, want %v", info.RenewalTime, tt.wantRenewalTime)
			}
		})
	}
}

func TestComputeRenewalInfo_MinRenewalInterval(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Credential expires in 5m10s, renewBefore=5m => renewal in 10s.
	// But 10s < MinRenewalInterval (30s), so should be clamped.
	pc := &ParsedCredential{
		Expiry:   now.Add(5*time.Minute + 10*time.Second),
		IssuedAt: now.Add(-55 * time.Minute),
	}

	info := ComputeRenewalInfo(pc, 5*time.Minute, now)

	if info.NeedsRenewal {
		t.Error("NeedsRenewal should be false (not yet in window)")
	}
	if info.TimeUntilRenewal != MinRenewalInterval {
		t.Errorf("TimeUntilRenewal = %v, want %v (MinRenewalInterval)", info.TimeUntilRenewal, MinRenewalInterval)
	}
}

func TestComputeRenewalInfo_MaxCredentialLifetime(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Credential with extremely far future expiry should be capped.
	farFuture := now.Add(10 * 365 * 24 * time.Hour) // 10 years
	pc := &ParsedCredential{
		Expiry:   farFuture,
		IssuedAt: now,
	}

	info := ComputeRenewalInfo(pc, 5*time.Minute, now)

	maxExpiry := now.Add(MaxCredentialLifetime)
	if !info.ExpiryTime.Equal(maxExpiry) {
		t.Errorf("ExpiryTime = %v, want %v (capped to MaxCredentialLifetime)", info.ExpiryTime, maxExpiry)
	}
}

func TestTimeUntilExpiry(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		expiry   time.Time
		wantDur  time.Duration
		wantSign int // 1 = positive, -1 = negative
	}{
		{
			name:     "expiry in the future",
			expiry:   now.Add(2 * time.Hour),
			wantDur:  2 * time.Hour,
			wantSign: 1,
		},
		{
			name:     "expiry in the past",
			expiry:   now.Add(-30 * time.Minute),
			wantDur:  30 * time.Minute,
			wantSign: -1,
		},
		{
			name:     "no expiry returns default TTL",
			expiry:   time.Time{},
			wantDur:  DefaultCredentialTTL,
			wantSign: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &ParsedCredential{Expiry: tt.expiry}
			got := TimeUntilExpiry(pc, now)

			if tt.wantSign > 0 && got != tt.wantDur {
				t.Errorf("TimeUntilExpiry() = %v, want %v", got, tt.wantDur)
			}
			if tt.wantSign < 0 && got != -tt.wantDur {
				t.Errorf("TimeUntilExpiry() = %v, want %v", got, -tt.wantDur)
			}
		})
	}
}
