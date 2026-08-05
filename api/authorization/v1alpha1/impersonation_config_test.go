// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestImpersonationConfigEffectiveUsername(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ic   *ImpersonationConfig
		want string
	}{
		{name: "nil config", ic: nil, want: ""},
		{name: "empty config", ic: &ImpersonationConfig{}, want: ""},
		{
			name: "serviceAccountRef renders the full username",
			ic:   &ImpersonationConfig{ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"}},
			want: "system:serviceaccount:team-a:applier",
		},
		{
			name: "serviceAccountRef missing namespace falls through to userName",
			ic:   &ImpersonationConfig{ServiceAccountRef: &SARef{Name: "applier"}, UserName: "jane"},
			want: "jane",
		},
		{
			name: "raw userName",
			ic:   &ImpersonationConfig{UserName: "jane@example.com"},
			want: "jane@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ic.EffectiveUsername(); got != tt.want {
				t.Errorf("EffectiveUsername() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestImpersonationConfigSelectedMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ic   *ImpersonationConfig
		want ImpersonationMode
	}{
		{name: "nil config selects nothing", ic: nil, want: ""},
		{name: "no identity selects nothing", ic: &ImpersonationConfig{}, want: ""},
		{
			name: "bare ServiceAccount username selects the serviceaccount mode",
			ic:   &ImpersonationConfig{ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"}},
			want: ImpersonationModeServiceAccount,
		},
		{
			// The KEP trap: adding a UID header makes onlyUsernameSet() false, so the
			// apiserver skips the serviceaccount mode and falls through to legacy.
			name: "ServiceAccount username plus UID falls back to legacy",
			ic: &ImpersonationConfig{
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				UID:               "uid-1",
			},
			want: "",
		},
		{
			name: "ServiceAccount username plus groups falls back to legacy",
			ic: &ImpersonationConfig{
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Groups:            []string{"dev"},
			},
			want: "",
		},
		{
			name: "ServiceAccount username plus extra falls back to legacy",
			ic: &ImpersonationConfig{
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Extra:             []ImpersonationExtra{{Key: "example.com/a", Values: []string{"1"}}},
			},
			want: "",
		},
		{
			name: "bare node username selects the arbitrary-node mode",
			ic:   &ImpersonationConfig{UserName: "system:node:worker-1"},
			want: ImpersonationModeArbitraryNode,
		},
		{
			name: "node username plus groups falls back to legacy",
			ic:   &ImpersonationConfig{UserName: "system:node:worker-1", Groups: []string{"system:nodes"}},
			want: "",
		},
		{
			name: "generic username selects the user-info mode",
			ic:   &ImpersonationConfig{UserName: "jane@example.com"},
			want: ImpersonationModeUserInfo,
		},
		{
			name: "generic username with uid, groups and extra still selects user-info",
			ic: &ImpersonationConfig{
				UserName: "jane@example.com",
				UID:      "uid-1",
				Groups:   []string{"dev"},
				Extra:    []ImpersonationExtra{{Key: "example.com/a", Values: []string{"1"}}},
			},
			want: ImpersonationModeUserInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ic.SelectedMode(); got != tt.want {
				t.Errorf("SelectedMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateImpersonationConfig(t *testing.T) {
	t.Parallel()

	fldPath := field.NewPath("spec", "impersonation")

	tests := []struct {
		name         string
		ic           *ImpersonationConfig
		wantErrs     int
		wantContains string
	}{
		{name: "nil config is valid", ic: nil},
		{name: "disabled empty config is valid", ic: &ImpersonationConfig{}},
		{
			name: "enabled with a serviceAccountRef is valid (existing behaviour preserved)",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
			},
		},
		{
			name:         "enabled without any identity is rejected",
			ic:           &ImpersonationConfig{Enabled: true},
			wantErrs:     1,
			wantContains: "exactly one of serviceAccountRef or userName is required",
		},
		{
			name: "enabled serviceAccountRef missing name and namespace",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{},
			},
			wantErrs:     2,
			wantContains: "name is required when impersonation is enabled",
		},
		// The header-mixing trap. All three variants must be rejected.
		{
			name: "serviceAccountRef plus uid is rejected",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				UID:               "uid-1",
			},
			wantErrs:     1,
			wantContains: "silently fall back to legacy impersonation",
		},
		{
			name: "serviceAccountRef plus groups is rejected",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Groups:            []string{"dev"},
			},
			wantErrs:     1,
			wantContains: "silently fall back to legacy impersonation",
		},
		{
			name: "serviceAccountRef plus extra is rejected",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Extra:             []ImpersonationExtra{{Key: "example.com/a", Values: []string{"1"}}},
			},
			wantErrs:     1,
			wantContains: "silently fall back to legacy impersonation",
		},
		{
			name: "serviceAccountRef plus all three is rejected three times",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				UID:               "uid-1",
				Groups:            []string{"dev"},
				Extra:             []ImpersonationExtra{{Key: "example.com/a", Values: []string{"1"}}},
			},
			wantErrs:     3,
			wantContains: "silently fall back to legacy impersonation",
		},
		{
			name: "serviceAccountRef plus userName is rejected",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				UserName:          "jane",
			},
			wantErrs:     1,
			wantContains: "mutually exclusive",
		},
		{
			name:         "uid without a userName is rejected",
			ic:           &ImpersonationConfig{UID: "uid-1"},
			wantErrs:     1,
			wantContains: "userName is required when uid is set",
		},
		{
			name:         "groups without a userName is rejected",
			ic:           &ImpersonationConfig{Groups: []string{"dev"}},
			wantErrs:     1,
			wantContains: "userName is required when groups are set",
		},
		{
			name:         "extra without a userName is rejected",
			ic:           &ImpersonationConfig{Extra: []ImpersonationExtra{{Key: "example.com/a", Values: []string{"1"}}}},
			wantErrs:     1,
			wantContains: "userName is required when extra is set",
		},
		{
			name:         "node username as an apply identity is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "system:node:worker-1"},
			wantErrs:     1,
			wantContains: "node usernames",
		},
		{
			name:         "ServiceAccount spelled as a raw userName is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "system:serviceaccount:team-a:applier"},
			wantErrs:     1,
			wantContains: "use serviceAccountRef",
		},
		{
			name:         "system:masters group is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "jane", Groups: []string{SystemMastersGroup}},
			wantErrs:     1,
			wantContains: "system:masters",
		},
		{
			name:         "empty group is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "jane", Groups: []string{""}},
			wantErrs:     1,
			wantContains: "empty string group",
		},
		// Extra key validation mirrors the apiserver's validateExtra().
		{
			name:         "empty extra key is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "jane", Extra: []ImpersonationExtra{{Key: "", Values: []string{"v"}}}},
			wantErrs:     1,
			wantContains: "empty string key in extra",
		},
		{
			name:         "non-lowercase extra key is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "jane", Extra: []ImpersonationExtra{{Key: "Example.com/a", Values: []string{"v"}}}},
			wantErrs:     1,
			wantContains: "non-lowercase key in extra",
		},
		{
			name:     "extra key that is not domain-prefixed is rejected",
			ic:       &ImpersonationConfig{Enabled: true, UserName: "jane", Extra: []ImpersonationExtra{{Key: "notadomain", Values: []string{"v"}}}},
			wantErrs: 1,
		},
		{
			name:         "empty extra values slice is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "jane", Extra: []ImpersonationExtra{{Key: "example.com/a"}}},
			wantErrs:     1,
			wantContains: "empty values in extra",
		},
		{
			name:         "empty-string extra value is rejected",
			ic:           &ImpersonationConfig{Enabled: true, UserName: "jane", Extra: []ImpersonationExtra{{Key: "example.com/a", Values: []string{""}}}},
			wantErrs:     1,
			wantContains: "empty string value in extra",
		},
		{
			name: "duplicate extra keys are rejected",
			ic: &ImpersonationConfig{Enabled: true, UserName: "jane", Extra: []ImpersonationExtra{
				{Key: "example.com/a", Values: []string{"1"}},
				{Key: "example.com/a", Values: []string{"2"}},
			}},
			wantErrs:     1,
			wantContains: "Duplicate value",
		},
		{
			name: "valid full user-info identity",
			ic: &ImpersonationConfig{
				Enabled:  true,
				UserName: "jane@example.com",
				UID:      "uid-1",
				Groups:   []string{"dev", "ops"},
				Extra:    []ImpersonationExtra{{Key: "example.com/scopes", Values: []string{"read", "write"}}},
				Mode:     ImpersonationModeUserInfo,
			},
		},
		// The declared mode must match what the apiserver will actually pick.
		{
			name: "declared mode mismatch is rejected",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Mode:              ImpersonationModeUserInfo,
			},
			wantErrs:     1,
			wantContains: `selects mode "serviceaccount", not "user-info"`,
		},
		{
			name: "declared mode matching the serviceaccount identity is accepted",
			ic: &ImpersonationConfig{
				Enabled:           true,
				ServiceAccountRef: &SARef{Namespace: "team-a", Name: "applier"},
				Mode:              ImpersonationModeServiceAccount,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			errs := validateImpersonationConfig(tt.ic, fldPath)
			if len(errs) != tt.wantErrs {
				t.Fatalf("got %d errors, want %d: %v", len(errs), tt.wantErrs, errs)
			}
			if tt.wantContains == "" {
				return
			}
			if !strings.Contains(errs.ToAggregate().Error(), tt.wantContains) {
				t.Errorf("errors %q do not contain %q", errs.ToAggregate().Error(), tt.wantContains)
			}
		})
	}
}

func TestValidateConstrainedImpersonationLimits(t *testing.T) {
	t.Parallel()

	fldPath := field.NewPath("spec", "roleLimits", "constrainedImpersonation")

	tests := []struct {
		name         string
		limits       *ConstrainedImpersonationLimits
		wantErrs     int
		wantContains string
	}{
		{name: "nil limits are valid", limits: nil},
		{name: "allowed with no further limits is valid", limits: &ConstrainedImpersonationLimits{Allowed: true}},
		{
			name: "valid full limits",
			limits: &ConstrainedImpersonationLimits{
				Allowed:                  true,
				AllowedModes:             []ImpersonationMode{ImpersonationModeUserInfo},
				AllowedIdentityResources: []ImpersonationIdentityResource{ImpersonationResourceUsers},
				ForbiddenActionVerbs:     []string{"delete"},
				ForbidLegacyFallback:     true,
			},
		},
		{
			name:         "unknown mode",
			limits:       &ConstrainedImpersonationLimits{Allowed: true, AllowedModes: []ImpersonationMode{"bogus"}},
			wantErrs:     1,
			wantContains: "Unsupported value",
		},
		{
			name:         "unknown identity resource",
			limits:       &ConstrainedImpersonationLimits{Allowed: true, AllowedIdentityResources: []ImpersonationIdentityResource{"bogus"}},
			wantErrs:     1,
			wantContains: "Unsupported value",
		},
		{
			name:         "pre-encoded forbidden action verb is rejected",
			limits:       &ConstrainedImpersonationLimits{Allowed: true, ForbiddenActionVerbs: []string{"impersonate-on:user-info:list"}},
			wantErrs:     1,
			wantContains: "must be the bare underlying verb",
		},
		{
			name:         "allowedModes with allowed=false is contradictory",
			limits:       &ConstrainedImpersonationLimits{Allowed: false, AllowedModes: []ImpersonationMode{ImpersonationModeUserInfo}},
			wantErrs:     1,
			wantContains: "have no effect while allowed is false",
		},
		{
			name: "empty forbidden prefix in identityNameLimits is rejected",
			limits: &ConstrainedImpersonationLimits{
				Allowed:            true,
				IdentityNameLimits: &NameMatchLimits{ForbiddenPrefixes: []string{""}},
			},
			wantErrs:     1,
			wantContains: "must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			errs := validateConstrainedImpersonationLimits(tt.limits, fldPath)
			if len(errs) != tt.wantErrs {
				t.Fatalf("got %d errors, want %d: %v", len(errs), tt.wantErrs, errs)
			}
			if tt.wantContains == "" {
				return
			}
			if !strings.Contains(errs.ToAggregate().Error(), tt.wantContains) {
				t.Errorf("errors %q do not contain %q", errs.ToAggregate().Error(), tt.wantContains)
			}
		})
	}
}
