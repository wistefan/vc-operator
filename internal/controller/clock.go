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

import "time"

// Clock provides an abstraction over time.Now() for testability.
// In production, RealClock is used. In tests, FakeClock allows
// controlling time progression to simulate credential expiry and renewal.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
}

// RealClock is a Clock implementation that delegates to time.Now().
// This is the default clock used in production.
type RealClock struct{}

// Now returns the current wall-clock time.
func (RealClock) Now() time.Time {
	return time.Now()
}

// FakeClock is a Clock implementation for testing that returns a
// controllable fixed time. Use SetTime to advance the clock and
// simulate time progression for credential expiry and renewal tests.
type FakeClock struct {
	// CurrentTime is the time returned by Now().
	CurrentTime time.Time
}

// Now returns the fake clock's current time.
func (c *FakeClock) Now() time.Time {
	return c.CurrentTime
}

// SetTime sets the fake clock to the given time.
func (c *FakeClock) SetTime(t time.Time) {
	c.CurrentTime = t
}

// Advance moves the fake clock forward by the given duration.
func (c *FakeClock) Advance(d time.Duration) {
	c.CurrentTime = c.CurrentTime.Add(d)
}
