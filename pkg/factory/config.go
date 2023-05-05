/*
 * N3IWF Configuration Factory
 */

package factory

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"

	"github.com/free5gc/n3iwf/internal/logger"
)

const (
	N3iwfDefaultTLSKeyLogPath  = "./log/n3iwfsslkey.log"
	N3iwfDefaultCertPemPath    = "./cert/n3iwf.pem"
	N3iwfDefaultPrivateKeyPath = "./cert/n3iwf.key"
	N3iwfDefaultConfigPath     = "./config/n3iwfcfg.yaml"
)

type N3IWFNFInfo struct {
	GlobalN3IWFID   GlobalN3IWFID     `yaml:"GlobalN3IWFID" valid:"required"`
	RanNodeName     string            `yaml:"Name,omitempty" valid:"optional"`
	SupportedTAList []SupportedTAItem `yaml:"SupportedTAList" valid:"required"`
}

type GlobalN3IWFID struct {
	PLMNID  PLMNID `yaml:"PLMNID" valid:"required"`
	N3IWFID uint16 `yaml:"N3IWFID" valid:"range(0|65535),required"` // with length 2 bytes
}

type SupportedTAItem struct {
	TAC               string              `yaml:"TAC" valid:"hexadecimal,stringlength(6|6),required"`
	BroadcastPLMNList []BroadcastPLMNItem `yaml:"BroadcastPLMNList" valid:"required"`
}

type BroadcastPLMNItem struct {
	PLMNID              PLMNID             `yaml:"PLMNID" valid:"required"`
	TAISliceSupportList []SliceSupportItem `yaml:"TAISliceSupportList" valid:"required"`
}

type PLMNID struct {
	Mcc string `yaml:"MCC" valid:"numeric,stringlength(3|3),required"`
	Mnc string `yaml:"MNC" valid:"numeric,stringlength(2|3),required"`
}

type SliceSupportItem struct {
	SNSSAI SNSSAIItem `yaml:"SNSSAI" valid:"required"`
}

type SNSSAIItem struct {
	SST string `yaml:"SST" valid:"hexadecimal,stringlength(1|1),required"`
	SD  string `yaml:"SD,omitempty" valid:"hexadecimal,stringlength(6|6),required"`
}

type AMFSCTPAddresses struct {
	IPAddresses []string `yaml:"IP" valid:"required"`
	Port        int      `yaml:"Port,omitempty" valid:"port,optional"` // Default port is 38412 if not defined.
}

func (a *AMFSCTPAddresses) Validate() (bool, error) {
	var errs govalidator.Errors

	for _, IPAddress := range a.IPAddresses {
		if !govalidator.IsHost(IPAddress) {
			err := errors.New("Invalid AMFSCTPAddresses.IP: " + IPAddress + ", does not validate as IP")
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return false, errs
	}

	return true, nil
}

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

func (c *Config) Validate() (bool, error) {
	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"required,in(1.0.5)"`
	Description string `yaml:"description,omitempty" valid:"type(string)"`
}

type Configuration struct {
	N3IWFInfo        N3IWFNFInfo        `yaml:"N3IWFInformation" valid:"required"`
	AMFSCTPAddresses []AMFSCTPAddresses `yaml:"AMFSCTPAddresses" valid:"required"`

	TCPPort              uint16     `yaml:"NASTCPPort" valid:"port,required"`
	IKEBindAddr          string     `yaml:"IKEBindAddress" valid:"host,required"`
	IPSecGatewayAddr     string     `yaml:"IPSecTunnelAddress" valid:"host,required"`
	UEIPAddressRange     string     `yaml:"UEIPAddressRange" valid:"cidr,required"`                // e.g. 10.0.1.0/24
	XfrmIfaceName        string     `yaml:"XFRMInterfaceName" valid:"stringlength(1|10),optional"` // must != 0
	XfrmIfaceId          uint32     `yaml:"XFRMInterfaceID" valid:"numeric,optional"`              // must != 0
	GTPBindAddr          string     `yaml:"GTPBindAddress" valid:"host,required"`
	FQDN                 string     `yaml:"FQDN" valid:"url,required"` // e.g. n3iwf.free5gc.org
	PrivateKey           string     `yaml:"PrivateKey" valid:"type(string),minstringlength(1),optional"`
	CertificateAuthority string     `yaml:"CertificateAuthority" valid:"type(string),minstringlength(1),optional"`
	Certificate          string     `yaml:"Certificate" valid:"type(string),minstringlength(1),optional"`
	LivenessCheck        TimerValue `yaml:"LivenessCheck" valid:"required"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
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

	if _, err := c.LivenessCheck.validate(); err != nil {
		return false, err
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type TimerValue struct {
	Enable        bool          `yaml:"enable" valid:"type(bool)"`
	TransFreq     time.Duration `yaml:"transFreq" valid:"type(time.Duration)"`
	MaxRetryTimes int32         `yaml:"maxRetryTimes,omitempty" valid:"type(int32)"`
}

func (t *TimerValue) validate() (bool, error) {
	if _, err := govalidator.ValidateStruct(t); err != nil {
		return false, appendInvalid(err)
	}

	return true, nil
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
	c.RLock()
	defer c.RUnlock()

	if c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Enable: enable,
			Level:  "info",
		}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level: level,
		}
	} else {
		c.Logger.Level = level
	}
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level:        "info",
			ReportCaller: reportCaller,
		}
	} else {
		c.Logger.ReportCaller = reportCaller
	}
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.Enable
}

func (c *Config) GetLogLevel() string {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return "info"
	}
	return c.Logger.Level
}

func (c *Config) GetLogReportCaller() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.ReportCaller
}
