package processconverter

import (
	"errors"
	"io"
	"os"

	yaml "go.yaml.in/yaml/v4"
)

const maxRulePerYamlFile = 500

func ReadNvSecurityRules(filepath string) ([]NvSecurityRule, error) {
	var errs error
	var loader *yaml.Loader
	var ret []NvSecurityRule
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	loader, err = yaml.NewLoader(f)
	if err != nil {
		return nil, err
	}

	for range maxRulePerYamlFile {
		var rule NvSecurityRule
		err = loader.Load(&rule)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			errs = errors.Join(errs, err)
			continue
		}
		ret = append(ret, rule)
	}
	return ret, errs
}
