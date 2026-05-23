package processconverter

import (
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
)

const maxRulePerYamlFile = 500

func ReadNvSecurityRules(filepath string) ([]NvSecurityRule, error) {
	var errs error
	var ret []NvSecurityRule
	// TODO: support streaming
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	decode := scheme.Codecs.UniversalDeserializer().Decode
	corev1.AddToScheme(scheme.Scheme)

	// TODO: Register scheme
	obj, gvk, err := decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode item: %w", err)
	}

	fmt.Printf("Loaded Kind: %s\n", gvk.Kind)

	list, ok := obj.(*corev1.List)
	if !ok {
		panic("Object is not a corev1.List")
	}

	for _, item := range list.Items {
		// Individual items are returned as runtime.RawExtension
		fmt.Printf("Found item: %s\n", string(item.Raw))
	}

	return ret, errs
}
