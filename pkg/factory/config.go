/*
 * N3IWF Configuration Factory
 */

package factory

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/mohae/deepcopy"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/sctp"
)

const (
	N3iwfDefaultTLSKeyLogPath string = "./log/n3iwfsslkey.log"
	N3iwfDefaultCertPemPath   string = "./cert/n3iwf.pem"
	N3iwfDefaultCertKeyPath   string = "./cert/n3iwf.key"
	N3iwfDefaultConfigPath    string = "./config/n3iwfcfg.yaml"
	N3iwfDefaultXfrmIfaceName string = "ipsec"
	N3iwfDefaultXfrmIfaceId   uint32 = 7
)

type N3IWFNFInfo struct {
	GlobalN3IWFID   *GlobalN3IWFID    `yaml:"GlobalN3IWFID" valid:"required"`
	RanNodeName     string            `yaml:"Name,omitempty" valid:"optional"`
	SupportedTAList []SupportedTAItem `yaml:"SupportedTAList" valid:"required"`
}

type GlobalN3IWFID struct {
	PLMNID  *PLMNID `yaml:"PLMNID" valid:"required"`
	N3IWFID uint16  `yaml:"N3IWFID" valid:"range(0|65535),required"` // with length 2 bytes
}

type SupportedTAItem struct {
	TAC               string              `yaml:"TAC" valid:"hexadecimal,stringlength(6|6),required"`
	BroadcastPLMNList []BroadcastPLMNItem `yaml:"BroadcastPLMNList" valid:"required"`
}

type BroadcastPLMNItem struct {
	PLMNID              *PLMNID            `yaml:"PLMNID" valid:"required"`
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
	SST int32  `yaml:"SST" valid:"required"`
	SD  string `yaml:"SD,omitempty" valid:"required,hexadecimal,stringlength(6|6)"`
}

type AMFSCTPAddresses struct {
	IPAddresses []string `yaml:"IP" valid:"required"`
	Port        int      `yaml:"Port,omitempty" valid:"port,optional"` // Default port is 38412 if not defined.
}

func (a *AMFSCTPAddresses) validate() error {
	var errs govalidator.Errors

	for _, IPAddress := range a.IPAddresses {
		if !govalidator.IsHost(IPAddress) {
			err := errors.New("Invalid AMFSCTPAddresses.IP: " + IPAddress + ", does not validate as IP")
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

func (c *Config) Validate() error {
	if configuration := c.Configuration; configuration != nil {
		for _, amfSCTPAddress := range configuration.AMFSCTPAddresses {
			if err := amfSCTPAddress.validate(); err != nil {
				return err
			}
		}
	}

	govalidator.TagMap["cidr"] = govalidator.Validator(func(str string) bool {
		return govalidator.IsCIDR(str)
	})

	_, err := govalidator.ValidateStruct(c)
	return appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"required,in(1.0.5)"`
	Description string `yaml:"description,omitempty" valid:"optional"`
}

type Configuration struct {
	N3IWFInfo        *N3IWFNFInfo       `yaml:"N3IWFInformation"        valid:"required"`
	LocalSctpAddr    string             `yaml:"localSctpAddr,omitempty" valid:"optional,host"`
	AMFSCTPAddresses []AMFSCTPAddresses `yaml:"AMFSCTPAddresses"        valid:"required"`

	TCPPort              int         `yaml:"NASTCPPort"           valid:"required,port"`
	IKEBindAddr          string      `yaml:"IKEBindAddress"       valid:"required,host"`
	IPSecGatewayAddr     string      `yaml:"IPSecTunnelAddress"   valid:"required,host"`
	UEIPAddressRange     string      `yaml:"UEIPAddressRange"     valid:"required,cidr"`               // e.g. 10.0.1.0/24
	XfrmIfaceName        string      `yaml:"XFRMInterfaceName"    valid:"optional,stringlength(1|10)"` // must != 0
	XfrmIfaceId          uint32      `yaml:"XFRMInterfaceID"      valid:"optional"`                    // must != 0
	GTPBindAddr          string      `yaml:"GTPBindAddress"       valid:"required,host"`
	FQDN                 string      `yaml:"FQDN"                 valid:"required,host"` // e.g. n3iwf.Saviah.com
	PrivateKey           string      `yaml:"PrivateKey"           valid:"optional"`
	CertificateAuthority string      `yaml:"CertificateAuthority" valid:"optional"`
	Certificate          string      `yaml:"Certificate"          valid:"optional"`
	LivenessCheck        *TimerValue `yaml:"LivenessCheck"        valid:"required"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

type TimerValue struct {
	Enable        bool          `yaml:"enable"        valid:"optional"`
	TransFreq     time.Duration `yaml:"transFreq"     valid:"required"`
	MaxRetryTimes int32         `yaml:"maxRetryTimes" valid:"optional"`
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

func (c *Config) GetGlobalN3iwfId() *GlobalN3IWFID {
	c.RLock()
	defer c.RUnlock()
	return deepcopy.Copy(c.Configuration.N3IWFInfo.GlobalN3IWFID).(*GlobalN3IWFID)
}

func (c *Config) GetRanNodeName() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.N3IWFInfo.RanNodeName
}

func (c *Config) GetLocalSctpAddr() *sctp.SCTPAddr {
	c.RLock()
	defer c.RUnlock()

	sctpAddr := new(sctp.SCTPAddr)
	localAddr := c.Configuration.LocalSctpAddr
	if localAddr != "" {
		ipAddr, err := net.ResolveIPAddr("ip", localAddr)
		if err == nil {
			sctpAddr = &sctp.SCTPAddr{
				IPAddrs: []net.IPAddr{*ipAddr},
			}
		}
	}
	return sctpAddr
}

func (c *Config) GetAmfSctpAddrs() []*sctp.SCTPAddr {
	c.RLock()
	defer c.RUnlock()

	var addrs []*sctp.SCTPAddr
	for _, amfAddr := range c.Configuration.AMFSCTPAddresses {
		sctpAddr := new(sctp.SCTPAddr)
		for _, ipStr := range amfAddr.IPAddresses {
			ipAddr, err := net.ResolveIPAddr("ip", ipStr)
			if err != nil {
				continue
			}
			sctpAddr.IPAddrs = append(sctpAddr.IPAddrs, *ipAddr)
		}
		if amfAddr.Port == 0 {
			sctpAddr.Port = 38412
		} else {
			sctpAddr.Port = amfAddr.Port
		}
		addrs = append(addrs, sctpAddr)
	}
	return addrs
}

func (c *Config) GetSupportedTAList() []SupportedTAItem {
	c.RLock()
	defer c.RUnlock()
	if len(c.Configuration.N3IWFInfo.SupportedTAList) > 0 {
		return deepcopy.Copy(c.Configuration.N3IWFInfo.SupportedTAList).([]SupportedTAItem)
	}
	return nil
}

func (c *Config) GetIKEBindAddr() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.IKEBindAddr
}

func (c *Config) GetIPSecGatewayAddr() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.IPSecGatewayAddr
}

func (c *Config) GetGTPBindAddr() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.GTPBindAddr
}

func (c *Config) GetNasTcpAddr() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.IPSecGatewayAddr + ":" + strconv.Itoa(c.Configuration.TCPPort)
}

func (c *Config) GetNasTcpPort() uint16 {
	c.RLock()
	defer c.RUnlock()
	return uint16(c.Configuration.TCPPort)
}

func (c *Config) GetFQDN() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.FQDN
}

func (c *Config) GetIKECAPemPath() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration.CertificateAuthority != "" {
		return c.Configuration.CertificateAuthority
	}
	return N3iwfDefaultCertPemPath
}

func (c *Config) GetIKECertPemPath() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration.Certificate != "" {
		return c.Configuration.Certificate
	}
	return N3iwfDefaultCertPemPath
}

func (c *Config) GetIKECertKeyPath() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration.PrivateKey != "" {
		return c.Configuration.PrivateKey
	}
	return N3iwfDefaultCertKeyPath
}

func (c *Config) GetUEIPAddrRange() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.UEIPAddressRange
}

func (c *Config) GetXfrmIfaceName() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration.XfrmIfaceName != "" {
		return c.Configuration.XfrmIfaceName
	}
	return N3iwfDefaultXfrmIfaceName
}

func (c *Config) GetXfrmIfaceId() uint32 {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration.XfrmIfaceId != 0 {
		return c.Configuration.XfrmIfaceId
	}
	return N3iwfDefaultXfrmIfaceId
}

func (c *Config) GetLivenessCheck() TimerValue {
	c.RLock()
	defer c.RUnlock()
	return *c.Configuration.LivenessCheck
}
