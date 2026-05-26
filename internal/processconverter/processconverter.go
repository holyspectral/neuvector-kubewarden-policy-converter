package processconverter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	nvv1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const maxRulePerYamlFile = 500

func ReadNvSecurityRules(filepath string) ([]*nvv1.NvSecurityRule, error) {
	var errs error
	var ret []*nvv1.NvSecurityRule

	// TODO: support streaming
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// TODO: support multiple yaml in one file
	decode := scheme.Codecs.UniversalDeserializer().Decode
	err = corev1.AddToScheme(scheme.Scheme)
	if err != nil {
		return nil, err
	}
	err = nvv1.AddToScheme(scheme.Scheme)
	if err != nil {
		return nil, err
	}

	obj, _, err := decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode item: %w", err)
	}

	switch item := obj.(type) {
	// When exporting from NV, it will be a corev1.List.
	case *corev1.List:
		for _, subitem := range item.Items {
			var rawRule runtime.Object
			rawRule, _, err = decode(subitem.Raw, nil, nil)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			rule, ok := rawRule.(*nvv1.NvSecurityRule)
			if !ok {
				errs = errors.Join(errs, errors.New("failed to parse NvSecurityRule"))
				continue
			}
			ret = append(ret, rule)
		}
	// When used in CRD, it will be an item.
	case *nvv1.NvSecurityRule:
		ret = append(ret, item)
	case *nvv1.NvSecurityRuleList:
		for _, rule := range item.Items {
			ret = append(ret, &rule)
		}
	default:
		errs = errors.Join(errs, fmt.Errorf("invalid object type: %T", item))
	}

	return ret, errs
}

// TODO: handle zero-drift
func ValidateSecurityRule(nvrule *nvv1.NvSecurityRule) error {
	// Verify that it comes with a service criteria.  If not, we can't convert this.
	if slices.ContainsFunc(nvrule.Spec.Target.Selector.Criteria, func(item nvv1.CriteriaEntry) bool {
		if item.Key == "service" && item.Value == nvrule.Name {
			return true
		}
		return false
	}) {
		return errors.New("no service is defined in criteria")
	}

	var reason string
	// Verify if it comes non-allow rule.
	if slices.ContainsFunc(nvrule.Spec.ProcessRule, func(item nvv1.NvSecurityProcessRule) bool {
		if item.Action != "allow" {
			reason = fmt.Sprintf("invalid action is detected: %s", item.Action)
			return true
		}
		if filepath.Base(item.Path) != item.Name {
			reason = fmt.Sprintf("non-default process name is detected: %s", item.Name)
			return true
		}
		return false
	}) {
		return fmt.Errorf("failed to validate security rule: %s", reason)
	}
	return nil
}

func ParseNvServiceName(name string, namespace string) (string, error) {
	if !strings.HasPrefix(name, "nv.") {
		return "", fmt.Errorf("the service name '%s' doesn't have 'nv.' prefix", name)
	}
	if !strings.HasSuffix(name, "."+namespace) {
		return "", fmt.Errorf("the service name '%s' doesn't have '.%s' suffix", name, namespace)
	}
	s := strings.TrimPrefix(name, "nv.")
	s = strings.TrimSuffix(s, "."+namespace)
	s = strings.TrimSpace(s)

	if len(s) == 0 {
		return "", errors.New("empty workload name")
	}
	return s, nil
}

func NvProcessRulesToWorkloadPolicyRules(nvrules []nvv1.NvSecurityProcessRule) *securityv1alpha1.WorkloadPolicyRules {
	var ret securityv1alpha1.WorkloadPolicyRules
	for _, rule := range nvrules {
		ret.Executables.Allowed = append(ret.Executables.Allowed, rule.Path)
	}
	return &ret
}

func searchContainerName(workloadName string, namespace string) (string, error) {
	return "", nil
}

func NvSecurityRuleToWorkloadPolicy(
	nvrule *nvv1.NvSecurityRule,
) (*securityv1alpha1.WorkloadPolicy, string, string, error) {
	if err := ValidateSecurityRule(nvrule); err != nil {
		return nil, "", "", fmt.Errorf("failed to validate nv security rule: %w", err)
	}

	workloadName, err := ParseNvServiceName(nvrule.Name, nvrule.Namespace)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse service name: %w", err)
	}
	// TODO: Access the API server to get the container name.

	containerName := "test"
	ret := &securityv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nvrule.Name,
			Namespace: nvrule.Namespace,
		},
		Spec: securityv1alpha1.WorkloadPolicySpec{
			Mode: "monitor", // TODO: export this to securityv1alpha1
			RulesByContainer: map[string]*securityv1alpha1.WorkloadPolicyRules{
				containerName: NvProcessRulesToWorkloadPolicyRules(nvrule.Spec.ProcessRule),
			},
		},
		Status: securityv1alpha1.WorkloadPolicyStatus{},
	}
	return ret, "workloadkind", workloadName, nil
}
