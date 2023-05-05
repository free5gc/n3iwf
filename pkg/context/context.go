package context

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"

	"git.cs.nctu.edu.tw/calee/sctp"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/util/idgenerator"
)

var n3iwfContext N3IWFContext

type N3IWFContext struct {
	NFInfo           factory.N3IWFNFInfo
	AMFSCTPAddresses []*sctp.SCTPAddr

	// ID generator
	RANUENGAPIDGenerator *idgenerator.IDGenerator
	TEIDGenerator        *idgenerator.IDGenerator

	// Pools
	AMFPool                sync.Map // map[string]*N3IWFAMF, SCTPAddr as key
	AMFReInitAvailableList sync.Map // map[string]bool, SCTPAddr as key
	IKESA                  sync.Map // map[uint64]*IKESecurityAssociation, SPI as key
	ChildSA                sync.Map // map[uint32]*ChildSecurityAssociation, inboundSPI as key
	GTPConnectionWithUPF   sync.Map // map[string]*gtpv1.UPlaneConn, UPF address as key
	AllocatedUEIPAddress   sync.Map // map[string]*N3IWFIkeUe, IPAddr as key
	AllocatedUETEID        sync.Map // map[uint32]*N3IWFRanUe, TEID as key
	IKEUePool              sync.Map // map[uint64]*N3IWFIkeUe, SPI as key
	RANUePool              sync.Map // map[int64]*N3IWFRanUe, RanUeNgapID as key
	IKESPIToNGAPId         sync.Map // map[uint64]RanUeNgapID, SPI as key
	NGAPIdToIKESPI         sync.Map // map[uint64]SPI, RanUeNgapID as key

	// N3IWF FQDN
	FQDN string

	// Security data
	CertificateAuthority []byte
	N3IWFCertificate     []byte
	N3IWFPrivateKey      *rsa.PrivateKey

	// UEIPAddressRange
	Subnet *net.IPNet

	// XFRM interface
	XfrmIfaceId         uint32
	XfrmIfaces          sync.Map // map[uint32]*netlink.Link, XfrmIfaceId as key
	XfrmIfaceName       string
	XfrmParentIfaceName string

	// Every UE's first UP IPsec will use default XFRM interface, additoinal UP IPsec will offset its XFRM id
	XfrmIfaceIdOffsetForUP uint32

	// N3IWF local address
	IKEBindAddress      string
	IPSecGatewayAddress string
	GTPBindAddress      string
	TCPPort             uint16

	// N3IWF NWu interface IPv4 packet connection
	NWuIPv4PacketConn *ipv4.PacketConn

	Ctx context.Context
	Wg  sync.WaitGroup

	NGAPServer *NGAPServer
	IKEServer  *IkeServer
}

func InitN3IWFContext() bool {
	var ok bool

	if factory.N3iwfConfig.Configuration == nil {
		logger.CtxLog.Error("No N3IWF configuration found")
		return false
	}

	n3iwfContext := N3IWFSelf()

	// N3IWF NF information
	n3iwfContext.NFInfo = factory.N3iwfConfig.Configuration.N3IWFInfo
	if ok = formatSupportedTAList(&n3iwfContext.NFInfo); !ok {
		return false
	}

	// AMF SCTP addresses
	if len(factory.N3iwfConfig.Configuration.AMFSCTPAddresses) == 0 {
		logger.CtxLog.Error("No AMF specified")
		return false
	} else {
		for _, amfAddress := range factory.N3iwfConfig.Configuration.AMFSCTPAddresses {
			amfSCTPAddr := new(sctp.SCTPAddr)
			// IP addresses
			for _, ipAddrStr := range amfAddress.IPAddresses {
				if ipAddr, err := net.ResolveIPAddr("ip", ipAddrStr); err != nil {
					logger.CtxLog.Errorf("Resolve AMF IP address failed: %+v", err)
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
		logger.CtxLog.Error("IKE bind address is empty")
		return false
	} else {
		n3iwfContext.IKEBindAddress = factory.N3iwfConfig.Configuration.IKEBindAddr
	}

	// IPSec gateway address
	if factory.N3iwfConfig.Configuration.IPSecGatewayAddr == "" {
		logger.CtxLog.Error("IPSec interface address is empty")
		return false
	} else {
		n3iwfContext.IPSecGatewayAddress = factory.N3iwfConfig.Configuration.IPSecGatewayAddr
	}

	// GTP bind address
	if factory.N3iwfConfig.Configuration.GTPBindAddr == "" {
		logger.CtxLog.Error("GTP bind address is empty")
		return false
	} else {
		n3iwfContext.GTPBindAddress = factory.N3iwfConfig.Configuration.GTPBindAddr
	}

	// TCP port
	if factory.N3iwfConfig.Configuration.TCPPort == 0 {
		logger.CtxLog.Error("TCP port is not defined")
		return false
	} else {
		n3iwfContext.TCPPort = factory.N3iwfConfig.Configuration.TCPPort
	}

	// FQDN
	if factory.N3iwfConfig.Configuration.FQDN == "" {
		logger.CtxLog.Error("FQDN is empty")
		return false
	} else {
		n3iwfContext.FQDN = factory.N3iwfConfig.Configuration.FQDN
	}

	// Private key
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.PrivateKey == "" {
			logger.CtxLog.Warn("No private key file path specified, load default key file...")
			keyPath = factory.N3iwfDefaultPrivateKeyPath
		} else {
			keyPath = factory.N3iwfConfig.Configuration.PrivateKey
		}

		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			logger.CtxLog.Errorf("Cannot read private key data from file: %+v", err)
			return false
		}
		block, _ := pem.Decode(content)
		if block == nil {
			logger.CtxLog.Error("Parse pem failed")
			return false
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			logger.CtxLog.Warnf("Parse PKCS8 private key failed: %+v", err)
			logger.CtxLog.Info("Parse using PKCS1...")

			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				logger.CtxLog.Errorf("Parse PKCS1 pricate key failed: %+v", err)
				return false
			}
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			logger.CtxLog.Error("Private key is not an rsa private key")
			return false
		}

		n3iwfContext.N3IWFPrivateKey = rsaKey
	}

	// Certificate authority
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.CertificateAuthority == "" {
			logger.CtxLog.Warn("No certificate authority file path specified, load default CA certificate...")
			keyPath = factory.N3iwfDefaultCertPemPath
		} else {
			keyPath = factory.N3iwfConfig.Configuration.CertificateAuthority
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			logger.CtxLog.Errorf("Cannot read certificate authority data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			logger.CtxLog.Error("Parse pem failed")
			return false
		}
		// Parse DER-encoded x509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.CtxLog.Errorf("Parse certificate authority failed: %+v", err)
			return false
		}
		// Get sha1 hash of subject public key info
		sha1Hash := sha1.New()
		if _, err := sha1Hash.Write(cert.RawSubjectPublicKeyInfo); err != nil {
			logger.CtxLog.Errorf("Hash function writing failed: %+v", err)
			return false
		}

		n3iwfContext.CertificateAuthority = sha1Hash.Sum(nil)
	}

	// Certificate
	{
		var keyPath string

		if factory.N3iwfConfig.Configuration.Certificate == "" {
			logger.CtxLog.Warn("No certificate file path specified, load default certificate...")
			keyPath = factory.N3iwfDefaultCertPemPath
		} else {
			keyPath = factory.N3iwfConfig.Configuration.Certificate
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			logger.CtxLog.Errorf("Cannot read certificate data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			logger.CtxLog.Error("Parse pem failed")
			return false
		}

		n3iwfContext.N3IWFCertificate = block.Bytes
	}

	// UE IP address range
	if factory.N3iwfConfig.Configuration.UEIPAddressRange == "" {
		logger.CtxLog.Error("UE IP address range is empty")
		return false
	} else {
		_, ueIPRange, err := net.ParseCIDR(factory.N3iwfConfig.Configuration.UEIPAddressRange)
		if err != nil {
			logger.CtxLog.Errorf("Parse CIDR failed: %+v", err)
			return false
		}
		n3iwfContext.Subnet = ueIPRange
	}

	// XFRM related
	ikeBindIfaceName, err := GetInterfaceName(factory.N3iwfConfig.Configuration.IKEBindAddr)
	if err != nil {
		logger.CtxLog.Error(err)
		return false
	} else {
		n3iwfContext.XfrmParentIfaceName = ikeBindIfaceName
	}

	if factory.N3iwfConfig.Configuration.XfrmIfaceName == "" {
		logger.CtxLog.Error("XFRM interface Name is empty, set to default \"ipsec\"")
		n3iwfContext.XfrmIfaceName = "ipsec"
	} else {
		n3iwfContext.XfrmIfaceName = factory.N3iwfConfig.Configuration.XfrmIfaceName
	}

	if factory.N3iwfConfig.Configuration.XfrmIfaceId == 0 {
		logger.CtxLog.Warn("XFRM interface id is not defined, set to default value 7")
		n3iwfContext.XfrmIfaceId = 7
	} else {
		n3iwfContext.XfrmIfaceId = factory.N3iwfConfig.Configuration.XfrmIfaceId
	}

	return true
}

func formatSupportedTAList(info *factory.N3IWFNFInfo) bool {
	for taListIndex := range info.SupportedTAList {
		supportedTAItem := &info.SupportedTAList[taListIndex]

		// Checking TAC
		if supportedTAItem.TAC == "" {
			logger.CtxLog.Error("TAC is mandatory.")
			return false
		}
		if len(supportedTAItem.TAC) < 6 {
			logger.CtxLog.Trace("Detect configuration TAC length < 6")
			supportedTAItem.TAC = strings.Repeat("0", 6-len(supportedTAItem.TAC)) + supportedTAItem.TAC
			logger.CtxLog.Tracef("Changed to %s", supportedTAItem.TAC)
		} else if len(supportedTAItem.TAC) > 6 {
			logger.CtxLog.Error("Detect configuration TAC length > 6")
			return false
		}

		// Checking SST and SD
		for plmnListIndex := range supportedTAItem.BroadcastPLMNList {
			broadcastPLMNItem := &supportedTAItem.BroadcastPLMNList[plmnListIndex]

			for sliceListIndex := range broadcastPLMNItem.TAISliceSupportList {
				sliceSupportItem := &broadcastPLMNItem.TAISliceSupportList[sliceListIndex]

				// SST
				if sliceSupportItem.SNSSAI.SST == "" {
					logger.CtxLog.Error("SST is mandatory.")
				}
				if len(sliceSupportItem.SNSSAI.SST) < 2 {
					logger.CtxLog.Trace("Detect configuration SST length < 2")
					sliceSupportItem.SNSSAI.SST = "0" + sliceSupportItem.SNSSAI.SST
					logger.CtxLog.Tracef("Change to %s", sliceSupportItem.SNSSAI.SST)
				} else if len(sliceSupportItem.SNSSAI.SST) > 2 {
					logger.CtxLog.Error("Detect configuration SST length > 2")
					return false
				}

				// SD
				if sliceSupportItem.SNSSAI.SD != "" {
					if len(sliceSupportItem.SNSSAI.SD) < 6 {
						logger.CtxLog.Trace("Detect configuration SD length < 6")
						sliceSupportItem.SNSSAI.SD = strings.Repeat("0", 6-len(sliceSupportItem.SNSSAI.SD)) + sliceSupportItem.SNSSAI.SD
						logger.CtxLog.Tracef("Change to %s", sliceSupportItem.SNSSAI.SD)
					} else if len(sliceSupportItem.SNSSAI.SD) > 6 {
						logger.CtxLog.Error("Detect configuration SD length > 6")
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

func init() {
	// init ID generator
	n3iwfContext.RANUENGAPIDGenerator = idgenerator.NewGenerator(0, math.MaxInt64)
	n3iwfContext.TEIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
}

// Create new N3IWF context
func N3IWFSelf() *N3IWFContext {
	return &n3iwfContext
}

func (context *N3IWFContext) NewN3iwfIkeUe(spi uint64) *N3IWFIkeUe {
	n3iwfIkeUe := new(N3IWFIkeUe)
	n3iwfIkeUe.init()
	context.IKEUePool.Store(spi, n3iwfIkeUe)
	return n3iwfIkeUe
}

func (context *N3IWFContext) NewN3iwfRanUe() *N3IWFRanUe {
	ranUeNgapId, err := context.RANUENGAPIDGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("New N3IWF UE failed: %+v", err)
		return nil
	}
	n3iwfRanUe := new(N3IWFRanUe)
	n3iwfRanUe.init(ranUeNgapId)
	context.RANUePool.Store(ranUeNgapId, n3iwfRanUe)
	n3iwfRanUe.TemporaryPDUSessionSetupData = new(PDUSessionSetupTemporaryData)

	return n3iwfRanUe
}

func (context *N3IWFContext) DeleteRanUe(ranUeNgapId int64) {
	context.RANUePool.Delete(ranUeNgapId)
	context.DeleteIkeSPIFromNgapId(ranUeNgapId)
}

func (context *N3IWFContext) DeleteIKEUe(spi uint64) {
	context.IKEUePool.Delete(spi)
	context.DeleteNgapIdFromIkeSPI(spi)
}

func (context *N3IWFContext) IkeUePoolLoad(spi uint64) (*N3IWFIkeUe, bool) {
	ikeUe, ok := context.IKEUePool.Load(spi)
	if ok {
		return ikeUe.(*N3IWFIkeUe), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) RanUePoolLoad(ranUeNgapId int64) (*N3IWFRanUe, bool) {
	ranUe, ok := context.RANUePool.Load(ranUeNgapId)
	if ok {
		return ranUe.(*N3IWFRanUe), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) IkeSpiNgapIdMapping(spi uint64, ranUeNgapId int64) {
	context.IKESPIToNGAPId.Store(spi, ranUeNgapId)
	context.NGAPIdToIKESPI.Store(ranUeNgapId, spi)
}

func (context *N3IWFContext) IkeSpiLoad(ranUeNgapId int64) (uint64, bool) {
	spi, ok := context.NGAPIdToIKESPI.Load(ranUeNgapId)
	if ok {
		return spi.(uint64), ok
	} else {
		return 0, ok
	}
}

func (context *N3IWFContext) NgapIdLoad(spi uint64) (int64, bool) {
	ranNgapId, ok := context.IKESPIToNGAPId.Load(spi)
	if ok {
		return ranNgapId.(int64), ok
	} else {
		return 0, ok
	}
}

func (context *N3IWFContext) DeleteNgapIdFromIkeSPI(spi uint64) {
	context.IKESPIToNGAPId.Delete(spi)
}

func (context *N3IWFContext) DeleteIkeSPIFromNgapId(ranUeNgapId int64) {
	context.NGAPIdToIKESPI.Delete(ranUeNgapId)
}

func (context *N3IWFContext) RanUeLoadFromIkeSPI(spi uint64) (*N3IWFRanUe, error) {
	ranNgapId, ok := context.IKESPIToNGAPId.Load(spi)
	if ok {
		ranUe, err := context.RanUePoolLoad(ranNgapId.(int64))
		if !err {
			return nil, fmt.Errorf("Cannot find RanUE from RanNgapId : %+v", ranNgapId)
		}
		return ranUe, nil
	} else {
		return nil, fmt.Errorf("Cannot find RanNgapId from IkeUe SPI : %+v", spi)
	}
}

func (context *N3IWFContext) IkeUeLoadFromNgapId(ranUeNgapId int64) (*N3IWFIkeUe, error) {
	spi, ok := context.NGAPIdToIKESPI.Load(ranUeNgapId)
	if ok {
		ikeUe, err := context.IkeUePoolLoad(spi.(uint64))
		if !err {
			return nil, fmt.Errorf("Cannot find IkeUe from spi : %+v", spi)
		}
		return ikeUe, nil
	} else {
		return nil, fmt.Errorf("Cannot find SPI from NgapId : %+v", ranUeNgapId)
	}
}

func (context *N3IWFContext) NewN3iwfAmf(sctpAddr string, conn *sctp.SCTPConn) *N3IWFAMF {
	amf := new(N3IWFAMF)
	amf.init(sctpAddr, conn)
	if item, loaded := context.AMFPool.LoadOrStore(sctpAddr, amf); loaded {
		logger.CtxLog.Warn("[Context] NewN3iwfAmf(): AMF entry already exists.")
		return item.(*N3IWFAMF)
	} else {
		return amf
	}
}

func (context *N3IWFContext) DeleteN3iwfAmf(sctpAddr string) {
	context.AMFPool.Delete(sctpAddr)
}

func (context *N3IWFContext) AMFPoolLoad(sctpAddr string) (*N3IWFAMF, bool) {
	amf, ok := context.AMFPool.Load(sctpAddr)
	if ok {
		return amf.(*N3IWFAMF), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) DeleteAMFReInitAvailableFlag(sctpAddr string) {
	context.AMFReInitAvailableList.Delete(sctpAddr)
}

func (context *N3IWFContext) AMFReInitAvailableListLoad(sctpAddr string) (bool, bool) {
	flag, ok := context.AMFReInitAvailableList.Load(sctpAddr)
	if ok {
		return flag.(bool), ok
	} else {
		return true, ok
	}
}

func (context *N3IWFContext) AMFReInitAvailableListStore(sctpAddr string, flag bool) {
	context.AMFReInitAvailableList.Store(sctpAddr, flag)
}

func (context *N3IWFContext) NewIKESecurityAssociation() *IKESecurityAssociation {
	ikeSecurityAssociation := new(IKESecurityAssociation)

	var maxSPI *big.Int = new(big.Int).SetUint64(math.MaxUint64)
	var localSPIuint64 uint64

	for {
		localSPI, err := rand.Int(rand.Reader, maxSPI)
		if err != nil {
			logger.CtxLog.Error("[Context] Error occurs when generate new IKE SPI")
			return nil
		}
		localSPIuint64 = localSPI.Uint64()
		if _, duplicate := context.IKESA.LoadOrStore(localSPIuint64, ikeSecurityAssociation); !duplicate {
			break
		}
	}

	ikeSecurityAssociation.LocalSPI = localSPIuint64

	return ikeSecurityAssociation
}

func (context *N3IWFContext) DeleteIKESecurityAssociation(spi uint64) {
	context.IKESA.Delete(spi)
}

func (context *N3IWFContext) IKESALoad(spi uint64) (*IKESecurityAssociation, bool) {
	securityAssociation, ok := context.IKESA.Load(spi)
	if ok {
		return securityAssociation.(*IKESecurityAssociation), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) DeleteGTPConnection(upfAddr string) {
	context.GTPConnectionWithUPF.Delete(upfAddr)
}

func (context *N3IWFContext) GTPConnectionWithUPFLoad(upfAddr string) (*gtpv1.UPlaneConn, bool) {
	conn, ok := context.GTPConnectionWithUPF.Load(upfAddr)
	if ok {
		return conn.(*gtpv1.UPlaneConn), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) GTPConnectionWithUPFStore(upfAddr string, conn *gtpv1.UPlaneConn) {
	context.GTPConnectionWithUPF.Store(upfAddr, conn)
}

func (context *N3IWFContext) NewInternalUEIPAddr(ikeUe *N3IWFIkeUe) net.IP {
	var ueIPAddr net.IP

	// TODO: Check number of allocated IP to detect running out of IPs
	for {
		ueIPAddr = generateRandomIPinRange(context.Subnet)
		if ueIPAddr != nil {
			if ueIPAddr.String() == context.IPSecGatewayAddress {
				continue
			}
			if _, ok := context.AllocatedUEIPAddress.LoadOrStore(ueIPAddr.String(), ikeUe); !ok {
				break
			}
		}
	}

	return ueIPAddr
}

func (context *N3IWFContext) DeleteInternalUEIPAddr(ipAddr string) {
	context.AllocatedUEIPAddress.Delete(ipAddr)
}

func (context *N3IWFContext) AllocatedUEIPAddressLoad(ipAddr string) (*N3IWFIkeUe, bool) {
	ikeUe, ok := context.AllocatedUEIPAddress.Load(ipAddr)
	if ok {
		return ikeUe.(*N3IWFIkeUe), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) NewTEID(ranUe *N3IWFRanUe) uint32 {
	teid64, err := context.TEIDGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("New TEID failed: %+v", err)
		return 0
	}
	teid32 := uint32(teid64)

	context.AllocatedUETEID.Store(teid32, ranUe)

	return teid32
}

func (context *N3IWFContext) DeleteTEID(teid uint32) {
	context.TEIDGenerator.FreeID(int64(teid))
	context.AllocatedUETEID.Delete(teid)
}

func (context *N3IWFContext) AllocatedUETEIDLoad(teid uint32) (*N3IWFRanUe, bool) {
	ranUe, ok := context.AllocatedUETEID.Load(teid)
	if ok {
		return ranUe.(*N3IWFRanUe), ok
	} else {
		return nil, ok
	}
}

func (context *N3IWFContext) AMFSelection(ueSpecifiedGUAMI *ngapType.GUAMI,
	ueSpecifiedPLMNId *ngapType.PLMNIdentity,
) *N3IWFAMF {
	var availableAMF *N3IWFAMF
	context.AMFPool.Range(func(key, value interface{}) bool {
		amf := value.(*N3IWFAMF)
		if amf.FindAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI) {
			availableAMF = amf
			return false
		} else {
			// Fail to find through GUAMI served by UE.
			// Try again using SelectedPLMNId
			if amf.FindAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedPLMNId) {
				availableAMF = amf
				return false
			} else {
				return true
			}
		}
	})
	return availableAMF
}

func generateRandomIPinRange(subnet *net.IPNet) net.IP {
	ipAddr := make([]byte, 4)
	randomNumber := make([]byte, 4)

	_, err := rand.Read(randomNumber)
	if err != nil {
		logger.CtxLog.Errorf("Generate random number for IP address failed: %+v", err)
		return nil
	}

	// TODO: elimenate network name, gateway, and broadcast
	for i := 0; i < 4; i++ {
		alter := randomNumber[i] & (subnet.Mask[i] ^ 255)
		ipAddr[i] = subnet.IP[i] + alter
	}

	return net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}
