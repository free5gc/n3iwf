/*
 * N3IWF Configuration Factory
 */

package factory

import (
	"gofree5gc/src/n3iwf/n3iwf_context"
)

type Configuration struct {
	N3IWFInfo            n3iwf_context.N3IWFNFInfo `yaml:"N3IWFInformation"`
	AMFAddress           []ConfigAMFAddr           `yaml:"AMFAddress"`
	IKEBindAddr          string                    `yaml:"IKEBindAddr"`
	IPSecGatewayAddr     string
	GTPBindAddr          string
	FQDN                 string // e.g. n3iwf.free5gc.org
	PrivateKey           string // file path
	CertificateAuthority string // file path
	Certificate          string // file path
	UEIPAddressRange     string // e.g. 10.0.1.0/24
	InterfaceMark        uint32 // must != 0, if not specified, random one
}

type ConfigAMFAddr struct {
	NetworkAddress string `yaml:"IP"`
	Port           int    `yaml:"Port,omitempty"`
}
