package util

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
)

var contextLog *logrus.Entry

func InitN3IWFContext() bool {
	var ok bool
	contextLog = logger.ContextLog

	if factory.N3iwfConfig.Configuration == nil {
		contextLog.Error("No N3IWF configuration found")
		return false
	}

	n3iwfContext := context.N3IWFSelf()

	// N3IWF NF information
	n3iwfContext.NFInfo = factory.N3iwfConfig.Configuration.N3IWFInfo
	if ok = formatSupportedTAList(&n3iwfContext.NFInfo); !ok {
		return false
	}

	// AMF SCTP addresses
	if len(factory.N3iwfConfig.Configuration.AMFSCTPAddresses) == 0 {
		contextLog.Error("No AMF specified")
		return false
	} else {
		for _, amfAddress := range factory.N3iwfConfig.Configuration.AMFSCTPAddresses {
			amfSCTPAddr := new(sctp.SCTPAddr)
			// IP addresses
			for _, ipAddrStr := range amfAddress.IPAddresses {
				if ipAddr, err := net.ResolveIPAddr("ip", ipAddrStr); err != nil {
					contextLog.Errorf("Resolve AMF IP address failed: %+v", err)
					return false
				} else {
					amfSCTPAddr.IPAddrs = append(amfSCTPAddr.IPAddrs, *ipAddr)
				}
			}
			// Port
			if amfAddress.Port == 0 {
				amfSCTPAddr.Port = 38412
			} else {
				amfSCTPAddr.Port = amfAddress.Port
			}
			// Append to context
			n3iwfContext.AMFSCTPAddresses = append(n3iwfContext.AMFSCTPAddresses, amfSCTPAddr)
		}
	}

	// IKE bind address
	if factory.N3iwfConfig.Configuration.IKEBindAddr == "" {
		contextLog.Error("IKE bind address is empty")
		return false
	} else {
		n3iwfContext.IKEBindAddress = factory.N3iwfConfig.Configuration.IKEBindAddr
	}

	// IPSec gateway address
	if factory.N3iwfConfig.Configuration.IPSecGatewayAddr == "" {
		contextLog.Error("IPSec interface address is empty")
		return false
	} else {
		n3iwfContext.IPSecGatewayAddress = factory.N3iwfConfig.Configuration.IPSecGatewayAddr
	}

	// GTP bind address
	if factory.N3iwfConfig.Configuration.GTPBindAddr == "" {
		contextLog.Error("GTP bind address is empty")
		return false
	} else {
		n3iwfContext.GTPBindAddress = factory.N3iwfConfig.Configuration.GTPBindAddr
	}

	// TCP port
	if factory.N3iwfConfig.Configuration.TCPPort == 0 {
		contextLog.Error("TCP port is not defined")
		return false
	} else {
		n3iwfContext.TCPPort = factory.N3iwfConfig.Configuration.TCPPort
	}

	// FQDN
	if factory.N3iwfConfig.Configuration.FQDN == "" {
		contextLog.Error("FQDN is empty")
		return false
	} else {
		n3iwfContext.FQDN = factory.N3iwfConfig.Configuration.FQDN
	}

	// Private key
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.PrivateKey == "" {
			contextLog.Warn("No private key file path specified, load default key file...")
			keyPath = N3iwfDefaultKeyPath
		} else {
			keyPath = factory.N3iwfConfig.Configuration.PrivateKey
		}

		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read private key data from file: %+v", err)
			return false
		}
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			contextLog.Warnf("Parse PKCS8 private key failed: %+v", err)
			contextLog.Info("Parse using PKCS1...")

			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				contextLog.Errorf("Parse PKCS1 pricate key failed: %+v", err)
				return false
			}
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			contextLog.Error("Private key is not an rsa private key")
			return false
		}

		n3iwfContext.N3IWFPrivateKey = rsaKey
	}

	// Certificate authority
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.CertificateAuthority == "" {
			contextLog.Warn("No certificate authority file path specified, load default CA certificate...")
			keyPath = N3iwfDefaultPemPath
		} else {
			keyPath = factory.N3iwfConfig.Configuration.CertificateAuthority
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read certificate authority data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}
		// Parse DER-encoded x509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			contextLog.Errorf("Parse certificate authority failed: %+v", err)
			return false
		}
		// Get sha1 hash of subject public key info
		sha1Hash := sha1.New()
		if _, err := sha1Hash.Write(cert.RawSubjectPublicKeyInfo); err != nil {
			contextLog.Errorf("Hash function writing failed: %+v", err)
			return false
		}

		n3iwfContext.CertificateAuthority = sha1Hash.Sum(nil)
	}

	// Certificate
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.Certificate == "" {
			contextLog.Warn("No certificate file path specified, load default certificate...")
			keyPath = N3iwfDefaultPemPath
		} else {
			keyPath = factory.N3iwfConfig.Configuration.Certificate
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read certificate data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}

		n3iwfContext.N3IWFCertificate = block.Bytes
	}

	// UE IP address range
	if factory.N3iwfConfig.Configuration.UEIPAddressRange == "" {
		contextLog.Error("UE IP address range is empty")
		return false
	} else {
		_, ueIPRange, err := net.ParseCIDR(factory.N3iwfConfig.Configuration.UEIPAddressRange)
		if err != nil {
			contextLog.Errorf("Parse CIDR failed: %+v", err)
			return false
		}
		n3iwfContext.Subnet = ueIPRange
	}

	// XFRM related
	ikeBindIfaceName, err := GetInterfaceName(factory.N3iwfConfig.Configuration.IKEBindAddr)
	if err != nil {
		contextLog.Error(err)
		return false
	} else {
		n3iwfContext.XfrmParentIfaceName = ikeBindIfaceName
	}

	if factory.N3iwfConfig.Configuration.XfrmIfaceName == "" {
		contextLog.Error("XFRM interface Name is empty, set to default \"ipsec\"")
		n3iwfContext.XfrmIfaceName = "ipsec"
	} else {
		n3iwfContext.XfrmIfaceName = factory.N3iwfConfig.Configuration.XfrmIfaceName
	}

	if factory.N3iwfConfig.Configuration.XfrmIfaceId == 0 {
		contextLog.Warn("XFRM interface id is not defined, set to default value 7")
		n3iwfContext.XfrmIfaceId = 7
	} else {
		n3iwfContext.XfrmIfaceId = factory.N3iwfConfig.Configuration.XfrmIfaceId
	}

	return true
}

func formatSupportedTAList(info *context.N3IWFNFInfo) bool {
	for taListIndex := range info.SupportedTAList {
		supportedTAItem := &info.SupportedTAList[taListIndex]

		// Checking TAC
		if supportedTAItem.TAC == "" {
			contextLog.Error("TAC is mandatory.")
			return false
		}
		if len(supportedTAItem.TAC) < 6 {
			contextLog.Trace("Detect configuration TAC length < 6")
			supportedTAItem.TAC = strings.Repeat("0", 6-len(supportedTAItem.TAC)) + supportedTAItem.TAC
			contextLog.Tracef("Changed to %s", supportedTAItem.TAC)
		} else if len(supportedTAItem.TAC) > 6 {
			contextLog.Error("Detect configuration TAC length > 6")
			return false
		}

		// Checking SST and SD
		for plmnListIndex := range supportedTAItem.BroadcastPLMNList {
			broadcastPLMNItem := &supportedTAItem.BroadcastPLMNList[plmnListIndex]

			for sliceListIndex := range broadcastPLMNItem.TAISliceSupportList {
				sliceSupportItem := &broadcastPLMNItem.TAISliceSupportList[sliceListIndex]

				// SST
				if sliceSupportItem.SNSSAI.SST == "" {
					contextLog.Error("SST is mandatory.")
				}
				if len(sliceSupportItem.SNSSAI.SST) < 2 {
					contextLog.Trace("Detect configuration SST length < 2")
					sliceSupportItem.SNSSAI.SST = "0" + sliceSupportItem.SNSSAI.SST
					contextLog.Tracef("Change to %s", sliceSupportItem.SNSSAI.SST)
				} else if len(sliceSupportItem.SNSSAI.SST) > 2 {
					contextLog.Error("Detect configuration SST length > 2")
					return false
				}

				// SD
				if sliceSupportItem.SNSSAI.SD != "" {
					if len(sliceSupportItem.SNSSAI.SD) < 6 {
						contextLog.Trace("Detect configuration SD length < 6")
						sliceSupportItem.SNSSAI.SD = strings.Repeat("0", 6-len(sliceSupportItem.SNSSAI.SD)) + sliceSupportItem.SNSSAI.SD
						contextLog.Tracef("Change to %s", sliceSupportItem.SNSSAI.SD)
					} else if len(sliceSupportItem.SNSSAI.SD) > 6 {
						contextLog.Error("Detect configuration SD length > 6")
						return false
					}
				}
			}
		}
	}

	return true
}

func GetInterfaceName(IPAddress string) (interfaceName string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "nil", err
	}

	res, err := net.ResolveIPAddr("ip4", IPAddress)
	if err != nil {
		return "", fmt.Errorf("Error resolving address '%s': %v", IPAddress, err)
	}
	IPAddress = res.String()

	for _, inter := range interfaces {
		addrs, err := inter.Addrs()
		if err != nil {
			return "nil", err
		}
		for _, addr := range addrs {
			if IPAddress == addr.String()[0:strings.Index(addr.String(), "/")] {
				return inter.Name, nil
			}
		}
	}
	return "", fmt.Errorf("Cannot find interface name")
}
