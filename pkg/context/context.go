package context

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/sctp"
	"github.com/free5gc/util/idgenerator"
)

var n3iwfContext *N3IWFContext

type n3iwf interface {
	Config() *factory.Config
	CancelContext() context.Context
}

type N3IWFContext struct {
	n3iwf

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

	// Security data
	CertificateAuthority []byte
	N3IWFCertificate     []byte
	N3IWFPrivateKey      *rsa.PrivateKey

	UeIPRange *net.IPNet

	// XFRM interface
	XfrmIfaces          sync.Map // map[uint32]*netlink.Link, XfrmIfaceId as key
	XfrmParentIfaceName string

	// Every UE's first UP IPsec will use default XFRM interface, additoinal UP IPsec will offset its XFRM id
	XfrmIfaceIdOffsetForUP uint32

	// N3IWF NWu interface IPv4 packet connection
	NWuIPv4PacketConn *ipv4.PacketConn

	NGAPServer *NGAPServer
	IKEServer  *IkeServer
}

func NewContext(n3iwf n3iwf) (*N3IWFContext, error) {
	n := &N3IWFContext{
		n3iwf:                n3iwf,
		RANUENGAPIDGenerator: idgenerator.NewGenerator(0, math.MaxInt64),
		TEIDGenerator:        idgenerator.NewGenerator(1, math.MaxUint32),
	}
	cfg := n3iwf.Config()

	// Private key
	block, _, err := decodePEM(cfg.GetIKECertKeyPath())
	if err != nil {
		return nil, errors.Wrapf(err, "IKE PrivKey")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.CtxLog.Warnf("Parse PKCS8 private key failed: %v", err)
		logger.CtxLog.Info("Parse using PKCS1...")

		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Errorf("Parse PKCS1 pricate key failed: %v", err)
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf("Private key is not an rsa private key")
	}
	n.N3IWFPrivateKey = rsaKey

	// Certificate authority
	block, _, err = decodePEM(cfg.GetIKECAPemPath())
	if err != nil {
		return nil, errors.Wrapf(err, "IKE CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Errorf("Parse certificate authority failed: %v", err)
	}
	// Get sha1 hash of subject public key info
	sha1Hash := sha1.New() // #nosec G401
	_, err = sha1Hash.Write(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, errors.Errorf("Hash function writing failed: %+v", err)
	}
	n.CertificateAuthority = sha1Hash.Sum(nil)

	// Certificate
	block, _, err = decodePEM(cfg.GetIKECertPemPath())
	if err != nil {
		return nil, errors.Wrapf(err, "IKE Cert")
	}
	n.N3IWFCertificate = block.Bytes

	// UE IP address range
	_, ueIPRange, err := net.ParseCIDR(cfg.GetUEIPAddrRange())
	if err != nil {
		return nil, errors.Errorf("Parse CIDR failed: %+v", err)
	}
	n.UeIPRange = ueIPRange

	// XFRM related
	ikeBindIfaceName, err := GetInterfaceName(cfg.GetIKEBindAddr())
	if err != nil {
		return nil, err
	}
	n.XfrmParentIfaceName = ikeBindIfaceName

	n3iwfContext = n
	return n, nil
}

func decodePEM(path string) (*pem.Block, []byte, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Cannot read file(%s)", path)
	}
	p, rest := pem.Decode(content)
	if p == nil {
		return nil, nil, errors.Errorf("Decode pem failed")
	}
	return p, rest, nil
}

func GetInterfaceName(IPAddress string) (interfaceName string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "nil", err
	}

	res, err := net.ResolveIPAddr("ip4", IPAddress)
	if err != nil {
		return "", fmt.Errorf("Error resolving address [%s]: %v", IPAddress, err)
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
	return "", fmt.Errorf("Cannot find interface name for IP[%s]", IPAddress)
}

// Create new N3IWF context
func N3IWFSelf() *N3IWFContext {
	return n3iwfContext
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

	cfg := context.Config()
	ipsecGwAddr := cfg.GetIPSecGatewayAddr()
	// TODO: Check number of allocated IP to detect running out of IPs
	for {
		ueIPAddr = generateRandomIPinRange(context.UeIPRange)
		if ueIPAddr != nil {
			if ueIPAddr.String() == ipsecGwAddr {
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
