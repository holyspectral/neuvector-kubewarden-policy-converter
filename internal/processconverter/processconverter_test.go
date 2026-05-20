package processconverter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/processconverter"
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
			description: "should successfully read a valid NvSecurityRule from simple.yaml",
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

// validateSimpleYamlRule validates the structure of a rule loaded from simple.yaml
func validateSimpleYamlRule(t *testing.T, rule processconverter.NvSecurityRule) {
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
