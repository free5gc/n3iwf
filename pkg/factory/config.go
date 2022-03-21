/*
 * N3IWF Configuration Factory
 */

package factory

import (
	"fmt"

	"github.com/asaskevich/govalidator"

	"github.com/free5gc/n3iwf/pkg/context"
	logger_util "github.com/free5gc/util/logger"
)

const (
	N3IWF_EXPECTED_CONFIG_VERSION = "1.0.1"
)

type Config struct {
	Info          *Info               `yaml:"info" valid:"required"`
	Configuration *Configuration      `yaml:"configuration" valid:"required"`
	Logger        *logger_util.Logger `yaml:"logger" valid:"optional"`
}

func (c *Config) Validate() (bool, error) {
	if info := c.Info; info != nil {
		if result, err := info.validate(); err != nil {
			return result, err
		}
	}

	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	if logger := c.Logger; logger != nil {
		if result, err := logger.Validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"type(string),required"`
	Description string `yaml:"description,omitempty" valid:"type(string),optional"`
}

func (i *Info) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(i)
	return result, appendInvalid(err)
}

type Configuration struct {
	N3IWFInfo        context.N3IWFNFInfo        `yaml:"N3IWFInformation" valid:"required"`
	AMFSCTPAddresses []context.AMFSCTPAddresses `yaml:"AMFSCTPAddresses" valid:"required"`

	IKEBindAddr          string `yaml:"IKEBindAddress" valid:"host,required"`
	IPSecGatewayAddr     string `yaml:"IPSecInterfaceAddress" valid:"host,required"`
	GTPBindAddr          string `yaml:"GTPBindAddress" valid:"host,required"`
	TCPPort              uint16 `yaml:"NASTCPPort" valid:"port,required"`
	FQDN                 string `yaml:"FQDN" valid:"url,required"`                   // e.g. n3iwf.free5gc.org
	UEIPAddressRange     string `yaml:"UEIPAddressRange" valid:"cidr,required"`      // e.g. 10.0.1.0/24
	InterfaceMark        uint32 `yaml:"IPSecInterfaceMark" valid:"numeric,optional"` // must != 0
	PrivateKey           string `yaml:"PrivateKey" valid:"type(string),minstringlength(1),optional"`
	CertificateAuthority string `yaml:"CertificateAuthority" valid:"type(string),minstringlength(1),optional"`
	Certificate          string `yaml:"Certificate" valid:"type(string),minstringlength(1),optional"`
}

func (c *Configuration) validate() (bool, error) {
	for _, amfSCTPAddress := range c.AMFSCTPAddresses {
		if result, err := amfSCTPAddress.Validate(); err != nil {
			return result, err
		}
	}

	govalidator.TagMap["cidr"] = govalidator.Validator(func(str string) bool {
		return govalidator.IsCIDR(str)
	})

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

func appendInvalid(err error) error {
	var errs govalidator.Errors

	if err == nil {
		return nil
	}

	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("Invalid %w", e))
	}

	return error(errs)
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
