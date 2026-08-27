// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestValidateExternalServiceAccountRefs(t *testing.T) {
	kind := schema.GroupKind{Group: GroupVersion.Group, Kind: BindDefinitionKind}
	base := BindDefinitionSpec{
		Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "controller", Namespace: "system"}},
	}

	tests := []struct {
		name      string
		refs      []SARef
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid reference",
			refs: []SARef{{Name: "controller", Namespace: "system"}},
		},
		{
			name:      "namespace required",
			refs:      []SARef{{Name: "controller"}},
			wantErr:   true,
			errSubstr: "namespace is required",
		},
		{
			name:      "name required",
			refs:      []SARef{{Namespace: "system"}},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name:      "duplicate reference",
			refs:      []SARef{{Name: "controller", Namespace: "system"}, {Name: "controller", Namespace: "system"}},
			wantErr:   true,
			errSubstr: "Duplicate value",
		},
		{
			name:      "subject is required",
			refs:      []SARef{{Name: "other", Namespace: "system"}},
			wantErr:   true,
			errSubstr: "must reference a ServiceAccount listed in spec.subjects",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := base
			spec.ExternalServiceAccountRefs = tt.refs
			err := validateExternalServiceAccountRefs(kind, "test", spec)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %v", tt.errSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
