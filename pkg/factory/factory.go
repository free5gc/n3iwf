/*
 * N3IWF Configuration Factory
 */

package factory

import (
	"fmt"
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"

	"github.com/free5gc/n3iwf/internal/logger"
)

var N3iwfConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		N3iwfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &N3iwfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := N3iwfConfig.GetVersion()

	if currentVersion != N3iwfExpectedConfigVersion {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, N3iwfExpectedConfigVersion)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
