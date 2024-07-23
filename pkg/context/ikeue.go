package context

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
)

const (
	AmfUeNgapIdUnspecified int64 = 0xffffffffff
)

type N3IWFIkeUe struct {
	N3iwfCtx *N3IWFContext

	/* UE identity */
	IPSecInnerIP     net.IP
	IPSecInnerIPAddr *net.IPAddr // Used to send UP packets to UE

	/* IKE Security Association */
	N3IWFIKESecurityAssociation   *IKESecurityAssociation
	N3IWFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key

	/* Temporary Mapping of two SPIs */
	// Exchange Message ID(including a SPI) and ChildSA(including a SPI)
	// Mapping of Message ID of exchange in IKE and Child SA when creating new child SA
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*ChildSecurityAssociation // Message ID as a key

	/* Security */
	Kn3iwf []uint8 // 32 bytes (256 bits), value is from NGAP IE "Security Key"

	/* NAS IKE Connection */
	IKEConnection *UDPSocketInfo

	// Length of PDU Session List
	PduSessionListLen int
}

type IkeMsgTemporaryData struct {
	SecurityAssociation      *ike_message.SecurityAssociation
	TrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	TrafficSelectorResponder *ike_message.TrafficSelectorResponder
}

type IKESecurityAssociation struct {
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Transforms for IKE SA
	EncryptionAlgorithm    *ike_message.Transform
	PseudorandomFunction   *ike_message.Transform
	IntegrityAlgorithm     *ike_message.Transform
	DiffieHellmanGroup     *ike_message.Transform
	ExpandedSequenceNumber *ike_message.Transform

	// Used for key generating
	ConcatenatedNonce      []byte
	DiffieHellmanSharedKey []byte

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication

	// State for IKE_AUTH
	State uint8

	// Temporary data stored for the use in later exchange
	InitiatorID              *ike_message.IdentificationInitiator
	InitiatorCertificate     *ike_message.Certificate
	IKEAuthResponseSA        *ike_message.SecurityAssociation
	TrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	TrafficSelectorResponder *ike_message.TrafficSelectorResponder
	LastEAPIdentifier        uint8

	// UDP Connection
	IKEConnection *UDPSocketInfo

	// Authentication data
	ResponderSignedOctets []byte
	InitiatorSignedOctets []byte

	// NAT detection
	// If UEIsBehindNAT == true, N3IWF should enable NAT traversal and
	// TODO: should support dynamic updating network address (MOBIKE)
	UEIsBehindNAT bool
	// If N3IWFIsBehindNAT == true, N3IWF should send UDP keepalive periodically
	N3IWFIsBehindNAT bool

	// IKE UE context
	IkeUE *N3IWFIkeUe

	// Temporary store the receive ike message
	TemporaryIkeMsg *IkeMsgTemporaryData

	DPDReqRetransTimer *Timer // The time from sending the DPD request to receiving the response
	CurrentRetryTimes  int32  // Accumulate the number of times the DPD response wasn't received
	IKESAClosedCh      chan struct{}
	IsUseDPD           bool
}

// Temporary State Data Args
const (
	ArgsUEUDPConn string = "UE UDP Socket Info"
)

type ChildSecurityAssociation struct {
	// SPI
	InboundSPI  uint32 // N3IWF Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// Associated XFRM interface
	XfrmIface netlink.Link

	XfrmStateList  []netlink.XfrmState
	XfrmPolicyList []netlink.XfrmPolicy

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet

	// Security
	EncryptionAlgorithm               uint16
	InitiatorToResponderEncryptionKey []byte
	ResponderToInitiatorEncryptionKey []byte
	IntegrityAlgorithm                uint16
	InitiatorToResponderIntegrityKey  []byte
	ResponderToInitiatorIntegrityKey  []byte
	ESN                               bool

	// Encapsulate
	EnableEncapsulate bool
	N3IWFPort         int
	NATPort           int

	// PDU Session IDs associated with this child SA
	PDUSessionIds []int64

	// IKE UE context
	IkeUE *N3IWFIkeUe
}

type UDPSocketInfo struct {
	Conn      *net.UDPConn
	N3IWFAddr *net.UDPAddr
	UEAddr    *net.UDPAddr
}

func (ikeUe *N3IWFIkeUe) init() {
	ikeUe.N3IWFChildSecurityAssociation = make(map[uint32]*ChildSecurityAssociation)
	ikeUe.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*ChildSecurityAssociation)
}

func (ikeUe *N3IWFIkeUe) Remove() error {
	if ikeUe.N3IWFIKESecurityAssociation.IsUseDPD {
		ikeUe.N3IWFIKESecurityAssociation.IKESAClosedCh <- struct{}{}
	}

	// remove from IKE UE context
	n3iwfCtx := ikeUe.N3iwfCtx
	n3iwfCtx.DeleteIKESecurityAssociation(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	n3iwfCtx.DeleteInternalUEIPAddr(ikeUe.IPSecInnerIP.String())

	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if err := ikeUe.DeleteChildSA(childSA); err != nil {
			return err
		}
	}
	n3iwfCtx.DeleteIKEUe(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)

	return nil
}

func (ikeUe *N3IWFIkeUe) DeleteChildSA(childSA *ChildSecurityAssociation) error {
	n3iwfCtx := ikeUe.N3iwfCtx
	iface := childSA.XfrmIface

	// Delete child SA xfrmState
	for _, xfrmState := range childSA.XfrmStateList {
		if err := netlink.XfrmStateDel(&xfrmState); err != nil {
			return fmt.Errorf("Delete xfrmstate error : %+v", err)
		}
	}
	// Delete child SA xfrmPolicy
	for _, xfrmPolicy := range childSA.XfrmPolicyList {
		if err := netlink.XfrmPolicyDel(&xfrmPolicy); err != nil {
			return fmt.Errorf("Delete xfrmPolicy error : %+v", err)
		}
	}

	if iface == nil || iface.Attrs().Name == "xfrmi-default" {
	} else if err := netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("Delete interface %s fail: %+v", iface.Attrs().Name, err)
	} else {
		n3iwfCtx.XfrmIfaces.Delete(uint32(childSA.XfrmStateList[0].Ifid))
	}

	delete(ikeUe.N3IWFChildSecurityAssociation, childSA.InboundSPI)

	return nil
}

// When N3IWF send CREATE_CHILD_SA request to N3UE, the inbound SPI of childSA will be only stored first until
// receive response and call CompleteChildSAWithProposal to fill the all data of childSA
func (ikeUe *N3IWFIkeUe) CreateHalfChildSA(msgID, inboundSPI uint32, pduSessionID int64) {
	childSA := new(ChildSecurityAssociation)
	childSA.InboundSPI = inboundSPI
	childSA.PDUSessionIds = append(childSA.PDUSessionIds, pduSessionID)
	// Link UE context
	childSA.IkeUE = ikeUe
	// Map Exchange Message ID and Child SA data until get paired response
	ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID] = childSA
}

func (ikeUe *N3IWFIkeUe) CompleteChildSA(msgID uint32, outboundSPI uint32,
	chosenSecurityAssociation *ike_message.SecurityAssociation,
) (*ChildSecurityAssociation, error) {
	childSA, ok := ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID]

	if !ok {
		return nil, fmt.Errorf("There's not a half child SA created by the exchange with message ID %d.", msgID)
	}

	// Remove mapping of exchange msg ID and child SA
	delete(ikeUe.TemporaryExchangeMsgIDChildSAMapping, msgID)

	if chosenSecurityAssociation == nil {
		return nil, errors.New("chosenSecurityAssociation is nil")
	}

	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, errors.New("No proposal")
	}

	childSA.OutboundSPI = outboundSPI

	if len(chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm) != 0 {
		childSA.EncryptionAlgorithm = chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm) != 0 {
		childSA.IntegrityAlgorithm = chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers) != 0 {
		if chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers[0].TransformID == 0 {
			childSA.ESN = false
		} else {
			childSA.ESN = true
		}
	}

	// Record to UE context with inbound SPI as key
	ikeUe.N3IWFChildSecurityAssociation[childSA.InboundSPI] = childSA
	// Record to N3IWF context with inbound SPI as key
	ikeUe.N3iwfCtx.ChildSA.Store(childSA.InboundSPI, childSA)

	return childSA, nil
}
