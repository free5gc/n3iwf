package xfrm

import (
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/ike/message"
)

// Log
var ikeLog *logrus.Entry

func init() {
	ikeLog = logger.IKELog
}

type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case message.ENCR_DES:
		return "cbc(des)"
	case message.ENCR_3DES:
		return "cbc(des3_ede)"
	case message.ENCR_CAST:
		return "cbc(cast5)"
	case message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case message.ENCR_NULL:
		return "ecb(cipher_null)"
	case message.ENCR_AES_CBC:
		return "cbc(aes)"
	case message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}

type XFRMIntegrityAlgorithmType uint16

func (xfrmIntegrityAlgorithmType XFRMIntegrityAlgorithmType) String() string {
	switch xfrmIntegrityAlgorithmType {
	case message.AUTH_HMAC_MD5_96:
		return "hmac(md5)"
	case message.AUTH_HMAC_SHA1_96:
		return "hmac(sha1)"
	case message.AUTH_AES_XCBC_96:
		return "xcbc(aes)"
	default:
		return ""
	}
}

func ApplyXFRMRule(n3iwf_is_initiator bool, xfrmiId uint32,
	childSecurityAssociation *context.ChildSecurityAssociation) error {
	// Build XFRM information data structure for incoming traffic.

	// Direction: {private_network} -> this_server
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if n3iwf_is_initiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.InitiatorToResponderIntegrityKey,
			}
		}
	}

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSecurityAssociation.InboundSPI)
	xfrmState.Ifid = int(xfrmiId)
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.ESN

	if childSecurityAssociation.EnableEncapsulate {
		xfrmState.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: childSecurityAssociation.NATPort,
			DstPort: childSecurityAssociation.N3IWFPort,
		}
	}

	// Commit xfrm state to netlink
	var err error
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		ikeLog.Errorf("Set XFRM rules failed: %+v", err)
		return errors.New("Set XFRM state rule failed")
	}

	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *xfrmState)

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Ifid = int(xfrmiId)
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		ikeLog.Errorf("Set XFRM rules failed: %+v", err)
		return errors.New("Set XFRM policy rule failed")
	}

	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *xfrmPolicy)

	// Direction: this_server -> {private_network}
	// State
	if n3iwf_is_initiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Spi = int(childSecurityAssociation.OutboundSPI)
	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src
	if xfrmState.Encap != nil {
		xfrmState.Encap.SrcPort, xfrmState.Encap.DstPort = xfrmState.Encap.DstPort, xfrmState.Encap.SrcPort
	}

	// Commit xfrm state to netlink
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		ikeLog.Errorf("Set XFRM rules failed: %+v", err)
		return errors.New("Set XFRM state rule failed")
	}

	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *xfrmState)

	// Policy
	xfrmPolicyTemplate.Spi = int(childSecurityAssociation.OutboundSPI)
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		ikeLog.Errorf("Set XFRM rules failed: %+v", err)
		return errors.New("Set XFRM policy rule failed")
	}

	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *xfrmPolicy)

	printSAInfo(n3iwf_is_initiator, xfrmiId, childSecurityAssociation)

	return nil
}

func printSAInfo(n3iwf_is_initiator bool, xfrmiId uint32, childSecurityAssociation *context.ChildSecurityAssociation) {
	var InboundEncryptionKey, InboundIntegrityKey, OutboundEncryptionKey, OutboundIntegrityKey []byte

	if n3iwf_is_initiator {
		InboundEncryptionKey = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		InboundIntegrityKey = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		OutboundEncryptionKey = childSecurityAssociation.InitiatorToResponderEncryptionKey
		OutboundIntegrityKey = childSecurityAssociation.InitiatorToResponderIntegrityKey
	} else {
		InboundEncryptionKey = childSecurityAssociation.InitiatorToResponderEncryptionKey
		InboundIntegrityKey = childSecurityAssociation.InitiatorToResponderIntegrityKey
		OutboundEncryptionKey = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		OutboundIntegrityKey = childSecurityAssociation.ResponderToInitiatorIntegrityKey
	}
	ikeLog.Debug("====== IPSec/Child SA Info ======")
	// ====== Inbound ======
	ikeLog.Debugf("XFRM interface if_id: %d", xfrmiId)
	ikeLog.Debugf("IPSec Inbound  SPI: 0x%016x", childSecurityAssociation.InboundSPI)
	ikeLog.Debugf("[UE:%+v] -> [N3IWF:%+v]",
		childSecurityAssociation.PeerPublicIPAddr, childSecurityAssociation.LocalPublicIPAddr)
	ikeLog.Debugf("IPSec Encryption Algorithm: %d", childSecurityAssociation.EncryptionAlgorithm)
	ikeLog.Debugf("IPSec Encryption Key: 0x%x", InboundEncryptionKey)
	ikeLog.Debugf("IPSec Integrity  Algorithm: %d", childSecurityAssociation.IntegrityAlgorithm)
	ikeLog.Debugf("IPSec Integrity  Key: 0x%x", InboundIntegrityKey)
	ikeLog.Debug("====== IPSec/Child SA Info ======")
	// ====== Outbound ======
	ikeLog.Debugf("XFRM interface if_id: %d", xfrmiId)
	ikeLog.Debugf("IPSec Outbound  SPI: 0x%016x", childSecurityAssociation.OutboundSPI)
	ikeLog.Debugf("[N3IWF:%+v] -> [UE:%+v]",
		childSecurityAssociation.LocalPublicIPAddr, childSecurityAssociation.PeerPublicIPAddr)
	ikeLog.Debugf("IPSec Encryption Algorithm: %d", childSecurityAssociation.EncryptionAlgorithm)
	ikeLog.Debugf("IPSec Encryption Key: 0x%x", OutboundEncryptionKey)
	ikeLog.Debugf("IPSec Integrity  Algorithm: %d", childSecurityAssociation.IntegrityAlgorithm)
	ikeLog.Debugf("IPSec Integrity  Key: 0x%x", OutboundIntegrityKey)
}

func SetupIPsecXfrmi(xfrmIfaceName, parentIfaceName string, xfrmIfaceId uint32,
	xfrmIfaceAddr net.IPNet) (netlink.Link, error) {
	var (
		xfrmi, parent netlink.Link
		err           error
	)

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, fmt.Errorf("Cannot find parent interface %s by name: %+v", parentIfaceName, err)
	}

	// ip link add <xfrmIfaceName> type xfrm dev <parent.Attrs().Name> if_id <xfrmIfaceId>
	link := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			Name:        xfrmIfaceName,
			ParentIndex: parent.Attrs().Index,
		},
		Ifid: xfrmIfaceId,
	}

	if err = netlink.LinkAdd(link); err != nil {
		return nil, err
	}

	if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
		return nil, err
	}

	ikeLog.Debugf("XFRM interface %s index is %d", xfrmIfaceName, xfrmi.Attrs().Index)

	// ip addr add xfrmIfaceAddr dev <xfrmIfaceName>
	linkIPSecAddr := &netlink.Addr{
		IPNet: &xfrmIfaceAddr,
	}

	if err := netlink.AddrAdd(xfrmi, linkIPSecAddr); err != nil {
		return nil, err
	}

	// ip link set <xfrmIfaceName> up
	if err := netlink.LinkSetUp(xfrmi); err != nil {
		return nil, err
	}

	return xfrmi, nil
}
