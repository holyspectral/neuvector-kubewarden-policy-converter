package processconverter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/processconverter"
	nvv1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
)

func TestReadNvSecurityRules(t *testing.T) {
	tests := []struct {
		name        string
		filepath    string
		wantErr     bool
		wantCount   int
		description string
	}{
		{
			name:        "valid simple yaml",
			filepath:    "testdata/simple.yaml",
			wantErr:     false,
			wantCount:   1,
			description: "should successfully read a valid NvSecurityRuleList exported from NeuVector",
		},
		{
			name:        "valid simple yaml",
			filepath:    "testdata/simple-crd.yaml",
			wantErr:     false,
			wantCount:   1,
			description: "should successfully read a valid NvSecurityRule CRD",
		},
		{
			name:        "non-existent file",
			filepath:    "testdata/does-not-exist.yaml",
			wantErr:     true,
			wantCount:   0,
			description: "should return error when file doesn't exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert relative path to absolute for the test
			testFilePath := filepath.Join("../../internal/processconverter", tt.filepath)
			if !filepath.IsAbs(tt.filepath) && tt.filepath != "testdata/does-not-exist.yaml" {
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatalf("failed to get working directory: %v", err)
				}
				testFilePath = filepath.Join(cwd, testFilePath)
			} else if tt.filepath == "testdata/does-not-exist.yaml" {
				testFilePath = tt.filepath
			}

			rules, err := processconverter.ReadNvSecurityRules(testFilePath)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadNvSecurityRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check count of returned rules
			if got := len(rules); got != tt.wantCount {
				t.Errorf("ReadNvSecurityRules() returned %d rules, want %d", got, tt.wantCount)
			}

			// Additional validation for successful cases
			if !tt.wantErr && len(rules) > 0 {
				validateSimpleYamlRule(t, rules[0])
			}
		})
	}
}

// validateSimpleYamlRule validates the structure of a rule loaded from simple.yaml.
func validateSimpleYamlRule(t *testing.T, rule *nvv1.NvSecurityRule) {
	t.Helper()

	// Validate metadata
	if rule.Name != "nv.kube-proxy.kube-system" {
		t.Errorf("expected rule name 'nv.kube-proxy.kube-system', got '%s'", rule.Name)
	}

	if rule.Namespace != "kube-system" {
		t.Errorf("expected namespace 'kube-system', got '%s'", rule.Namespace)
	}

	if rule.Kind != "NvSecurityRule" {
		t.Errorf("expected kind 'NvSecurityRule', got '%s'", rule.Kind)
	}

	// Validate process rules exist
	if len(rule.Spec.ProcessRule) == 0 {
		t.Error("expected process rules to be present")
	}

	// Validate first process rule
	if len(rule.Spec.ProcessRule) > 0 {
		firstProcess := rule.Spec.ProcessRule[0]
		if firstProcess.Name != "ip6tables" {
			t.Errorf("expected first process name 'ip6tables', got '%s'", firstProcess.Name)
		}
		if firstProcess.Path != "/usr/sbin/xtables-nft-multi" {
			t.Errorf("expected first process path '/usr/sbin/xtables-nft-multi', got '%s'", firstProcess.Path)
		}
		if firstProcess.Action != "allow" {
			t.Errorf("expected first process action 'allow', got '%s'", firstProcess.Action)
		}
	}

	// Validate process profile
	if rule.Spec.ProcessProfile == nil {
		t.Error("expected process profile to be present")
	} else {
		if rule.Spec.ProcessProfile.Baseline == nil || *rule.Spec.ProcessProfile.Baseline != "zero-drift" {
			t.Error("expected baseline to be 'zero-drift'")
		}
		if rule.Spec.ProcessProfile.Mode == nil || *rule.Spec.ProcessProfile.Mode != "Discover" {
			t.Error("expected mode to be 'Discover'")
		}
	}

	// Validate target
	if rule.Spec.Target.Selector.Name != "nv.kube-proxy.kube-system" {
		t.Errorf("expected target selector name 'nv.kube-proxy.kube-system', got '%s'", rule.Spec.Target.Selector.Name)
	}
}

func TestParseNvServiceName(t *testing.T) {
	tests := []struct {
		name      string
		inputName string
		namespace string
		want      string
		wantErr   bool
	}{
		{
			name:      "name with nv prefix and namespace suffix",
			inputName: "nv.kube-proxy.kube-system",
			namespace: "kube-system",
			want:      "kube-proxy",
			wantErr:   false,
		},
		{
			name:      "complex service name",
			inputName: "nv.my-app-service.production",
			namespace: "production",
			want:      "my-app-service",
			wantErr:   false,
		},
		{
			name:      "minimal valid name",
			inputName: "nv.service.ns",
			namespace: "ns",
			want:      "service",
			wantErr:   false,
		},
		{
			name:      "missing nv prefix",
			inputName: "my-service.default",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "missing namespace suffix",
			inputName: "nv.my-service",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "wrong namespace suffix",
			inputName: "nv.my-service.prod",
			namespace: "staging",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "empty name",
			inputName: "",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "only nv prefix with empty namespace - empty workload",
			inputName: "nv.",
			namespace: "",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "service name equals namespace",
			inputName: "nv.default.default",
			namespace: "default",
			want:      "default",
			wantErr:   false,
		},
		{
			name:      "not recommended service name with dot",
			inputName: "nv.default.default.default.namespace",
			namespace: "namespace",
			want:      "default.default.default",
			wantErr:   false,
		},
		{
			name:      "workload name is only dots - not empty after trim",
			inputName: "nv...namespace",
			namespace: "namespace",
			want:      ".",
			wantErr:   false,
		},
		{
			name:      "empty workload after trim - whitespace only",
			inputName: "nv.   .default",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "workload name with leading/trailing spaces",
			inputName: "nv. service .namespace",
			namespace: "namespace",
			want:      "service",
			wantErr:   false,
		},
		{
			name:      "workload with leading dot after prefix removal",
			inputName: "nv..kube-system.kube-system",
			namespace: "kube-system",
			want:      ".kube-system",
			wantErr:   false,
		},
		{
			name:      "exact pattern nv.<namespace>.<namespace> results in namespace name",
			inputName: "nv.ns.ns",
			namespace: "ns",
			want:      "ns",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := processconverter.ParseNvServiceName(tt.inputName, tt.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"ParseNvServiceName(%q, %q) error = %v, wantErr %v",
					tt.inputName,
					tt.namespace,
					err,
					tt.wantErr,
				)
				return
			}
			if got != tt.want {
				t.Errorf("ParseNvServiceName(%q, %q) = %q, want %q", tt.inputName, tt.namespace, got, tt.want)
			}
		})
	}
}
