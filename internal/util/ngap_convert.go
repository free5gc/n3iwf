package util

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
)

func PlmnIdToNgap(plmnId factory.PLMNID) (ngapPlmnId ngapType.PLMNIdentity) {
	var hexString string
	mcc := strings.Split(plmnId.Mcc, "")
	mnc := strings.Split(plmnId.Mnc, "")
	if len(plmnId.Mnc) == 2 {
		hexString = mcc[1] + mcc[0] + "f" + mcc[2] + mnc[1] + mnc[0]
	} else {
		hexString = mcc[1] + mcc[0] + mnc[0] + mcc[2] + mnc[2] + mnc[1]
	}
	var err error
	ngapPlmnId.Value, err = hex.DecodeString(hexString)
	if err != nil {
		logger.UtilLog.Errorf("DecodeString error: %+v", err)
	}
	return
}

func N3iwfIdToNgap(n3iwfId uint16) (ngapN3iwfId *aper.BitString) {
	ngapN3iwfId = new(aper.BitString)
	ngapN3iwfId.Bytes = make([]byte, 2)
	binary.BigEndian.PutUint16(ngapN3iwfId.Bytes, n3iwfId)
	ngapN3iwfId.BitLength = 16
	return
}

// IPAddressToString converts the NGAP transport-layer BIT STRING without
// changing the 38.414 IPv4/IPv6/dual-stack layout used by the legacy helper.
func IPAddressToString(ipAddr ngapType.TransportLayerAddress) (ipv4Addr, ipv6Addr string) {
	ip := ipAddr.Value
	switch ip.BitLength {
	case 32:
		if len(ip.Bytes) >= net.IPv4len {
			ipv4Addr = net.IP(ip.Bytes[:net.IPv4len]).String()
		}
	case 128:
		if len(ip.Bytes) >= net.IPv6len {
			ipv6Addr = net.IP(ip.Bytes[:net.IPv6len]).String()
		}
	case 160:
		if len(ip.Bytes) >= net.IPv4len+net.IPv6len {
			ipv4Addr = net.IP(ip.Bytes[:net.IPv4len]).String()
			ipv6Addr = net.IP(ip.Bytes[net.IPv4len : net.IPv4len+net.IPv6len]).String()
		}
	}
	return
}

// IPAddressToNgap preserves the legacy first-32-bits IPv4 followed by
// 128-bits IPv6 representation for dual-stack addresses.
func IPAddressToNgap(ipv4Addr, ipv6Addr string) ngapType.TransportLayerAddress {
	var result ngapType.TransportLayerAddress
	if ipv4Addr == "" && ipv6Addr == "" {
		logger.UtilLog.Warn("IPAddressToNgap: both IPv4 and IPv6 are empty")
		return result
	}

	var encoded []byte
	switch {
	case ipv4Addr != "" && ipv6Addr != "":
		ipv4 := net.ParseIP(ipv4Addr).To4()
		ipv6 := net.ParseIP(ipv6Addr).To16()
		if ipv4 == nil || ipv6 == nil {
			logger.UtilLog.Warnf("IPAddressToNgap: invalid address IPv4=%q IPv6=%q", ipv4Addr, ipv6Addr)
			return result
		}
		encoded = append(append([]byte{}, ipv4...), ipv6...)
	case ipv4Addr != "":
		ipv4 := net.ParseIP(ipv4Addr).To4()
		if ipv4 == nil {
			logger.UtilLog.Warnf("IPAddressToNgap: invalid IPv4 address %q", ipv4Addr)
			return result
		}
		encoded = append([]byte{}, ipv4...)
	default:
		ipv6 := net.ParseIP(ipv6Addr).To16()
		if ipv6 == nil {
			logger.UtilLog.Warnf("IPAddressToNgap: invalid IPv6 address %q", ipv6Addr)
			return result
		}
		encoded = append([]byte{}, ipv6...)
	}
	result.Value = aper.BitString{Bytes: encoded, BitLength: uint64(len(encoded) * 8)}
	return result
}

func PortNumberToNgap(port int32) ngapType.PortNumber {
	result := ngapType.PortNumber{Value: make([]byte, 2)}
	binary.BigEndian.PutUint16(result.Value, uint16(port))
	return result
}

// AmfIdToNgap keeps the legacy 8/10/6 bit split of a 24-bit AMF identifier.
func AmfIdToNgap(amfID string) (regionID, setID, pointerID aper.BitString) {
	if len(amfID) != 6 {
		logger.UtilLog.Warnf("AmfIdToNgap: AMF ID must contain 6 hexadecimal digits: %q", amfID)
		return
	}
	var err error
	regionID, err = legacyHexToBitString(amfID[:2], 8)
	if err != nil {
		logger.UtilLog.Warnf("AmfIdToNgap: region ID: %v", err)
		return aper.BitString{}, aper.BitString{}, aper.BitString{}
	}
	setID, err = legacyHexToBitString(amfID[2:5], 10)
	if err != nil {
		logger.UtilLog.Warnf("AmfIdToNgap: set ID: %v", err)
		return aper.BitString{}, aper.BitString{}, aper.BitString{}
	}
	lastOctet, err := hex.DecodeString(amfID[4:])
	if err != nil {
		logger.UtilLog.Warnf("AmfIdToNgap: pointer ID: %v", err)
		return aper.BitString{}, aper.BitString{}, aper.BitString{}
	}
	if err = pointerID.FromBytes(lastOctet, 2, 6); err != nil {
		logger.UtilLog.Warnf("AmfIdToNgap: pointer ID: %v", err)
		return aper.BitString{}, aper.BitString{}, aper.BitString{}
	}
	return
}

// legacyHexToBitString deliberately appends a low nibble to odd-length input.
// That differs from aper.BitString.FromHex, which prepends a high nibble, and
// is required to preserve the pre-PR AMF Set ID wire layout.
func legacyHexToBitString(value string, bitLength int) (aper.BitString, error) {
	if len(value) != (bitLength+3)/4 {
		return aper.BitString{}, fmt.Errorf("hex length %d does not match bit length %d", len(value), bitLength)
	}
	if len(value)%2 != 0 {
		value += "0"
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return aper.BitString{}, err
	}
	result := aper.BitString{Bytes: decoded, BitLength: uint64(bitLength)}
	mask := byte(0xff) << uint(8-bitLength%8)
	if mask != 0 {
		result.Bytes[len(result.Bytes)-1] &= mask
	}
	return result, nil
}

func ValidateTransportLayerAddress(
	address ngapType.CPTransportLayerInformation,
) (ngapType.TransportLayerAddress, error) {
	switch value := address.Choice.(type) {
	case *ngapType.TransportLayerAddress:
		if value == nil {
			return ngapType.TransportLayerAddress{}, fmt.Errorf("transport layer address is nil")
		}
		return *value, nil
	default:
		return ngapType.TransportLayerAddress{},
			fmt.Errorf("unsupported CP transport layer information choice %T", address.Choice)
	}
}
