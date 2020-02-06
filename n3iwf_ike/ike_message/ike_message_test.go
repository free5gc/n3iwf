package ike_message

import (
	"crypto/aes"
	"crypto/cipher"
	Crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	Mrand "math/rand"
	"net"
	"testing"
)

var conn net.Conn

func init() {
	conn, _ = net.Dial("udp", "127.0.0.1:500")
}

func TestHandler(t *testing.T) {
	testPacket := &IKEMessage{}

	// random an SPI
	src := Mrand.NewSource(63579)
	localRand := Mrand.New(src)
	ispi := localRand.Uint64()

	testPacket.InitiatorSPI = ispi
	testPacket.Version = 0x20
	testPacket.ExchangeType = 34 // IKE_SA_INIT
	testPacket.Flags = 16        // flagI is set
	testPacket.MessageID = 0     // for IKE_SA_INIT

	testSA := &SecurityAssociation{}

	testProposal1 := &Proposal{}
	testProposal1.ProposalNumber = 1 // first
	testProposal1.ProtocolID = 1     // IKE

	testtransform1 := &Transform{}
	testtransform1.TransformType = 1 // ENCR
	testtransform1.TransformID = 12  // ENCR_AES_CBC
	testtransform1.AttributePresent = true
	testtransform1.AttributeFormat = 1
	testtransform1.AttributeType = 14
	testtransform1.AttributeValue = 128

	testProposal1.EncryptionAlgorithm = append(testProposal1.EncryptionAlgorithm, testtransform1)

	testtransform2 := &Transform{}
	testtransform2.TransformType = 1 // ENCR
	testtransform2.TransformID = 12  // ENCR_AES_CBC
	testtransform2.AttributePresent = true
	testtransform2.AttributeFormat = 1
	testtransform2.AttributeType = 14
	testtransform2.AttributeValue = 192

	testProposal1.EncryptionAlgorithm = append(testProposal1.EncryptionAlgorithm, testtransform2)

	testtransform3 := &Transform{}
	testtransform3.TransformType = 3 // INTEG
	testtransform3.TransformID = 5   // AUTH_AES_XCBC_96
	testtransform3.AttributePresent = false

	testProposal1.IntegrityAlgorithm = append(testProposal1.IntegrityAlgorithm, testtransform3)

	testtransform4 := &Transform{}
	testtransform4.TransformType = 3 // INTEG
	testtransform4.TransformID = 2   // AUTH_HMAC_SHA1_96
	testtransform4.AttributePresent = false

	testProposal1.IntegrityAlgorithm = append(testProposal1.IntegrityAlgorithm, testtransform4)

	testSA.Proposals = append(testSA.Proposals, testProposal1)

	testProposal2 := &Proposal{}
	testProposal2.ProposalNumber = 2 // second
	testProposal2.ProtocolID = 1     // IKE

	testtransform1 = &Transform{}
	testtransform1.TransformType = 1 // ENCR
	testtransform1.TransformID = 12  // ENCR_AES_CBC
	testtransform1.AttributePresent = true
	testtransform1.AttributeFormat = 1
	testtransform1.AttributeType = 14
	testtransform1.AttributeValue = 128

	testProposal2.EncryptionAlgorithm = append(testProposal2.EncryptionAlgorithm, testtransform1)

	testtransform2 = &Transform{}
	testtransform2.TransformType = 1 // ENCR
	testtransform2.TransformID = 12  // ENCR_AES_CBC
	testtransform2.AttributePresent = true
	testtransform2.AttributeFormat = 1
	testtransform2.AttributeType = 14
	testtransform2.AttributeValue = 192

	testProposal2.EncryptionAlgorithm = append(testProposal2.EncryptionAlgorithm, testtransform2)

	testtransform3 = &Transform{}
	testtransform3.TransformType = 3 // INTEG
	testtransform3.TransformID = 1   // AUTH_HMAC_MD5_96
	testtransform3.AttributePresent = false

	testProposal2.IntegrityAlgorithm = append(testProposal2.IntegrityAlgorithm, testtransform3)

	testtransform4 = &Transform{}
	testtransform4.TransformType = 3 // INTEG
	testtransform4.TransformID = 2   // AUTH_HMAC_SHA1_96
	testtransform4.AttributePresent = false

	testProposal2.IntegrityAlgorithm = append(testProposal2.IntegrityAlgorithm, testtransform4)

	testSA.Proposals = append(testSA.Proposals, testProposal2)

	testPacket.IKEPayload = append(testPacket.IKEPayload, testSA)

	testKE := &KeyExchange{}

	testKE.DiffieHellmanGroup = 1
	for i := 0; i < 8; i++ {
		partKeyExchangeData := make([]byte, 8)
		binary.BigEndian.PutUint64(partKeyExchangeData, 7482105748278537214)
		testKE.KeyExchangeData = append(testKE.KeyExchangeData, partKeyExchangeData...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testKE)

	testIDr := &IdentificationResponder{}

	testIDr.IDType = 3
	for i := 0; i < 8; i++ {
		partIdentification := make([]byte, 8)
		binary.BigEndian.PutUint64(partIdentification, 4378215321473912643)
		testIDr.IDData = append(testIDr.IDData, partIdentification...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testIDr)

	testCert := &Certificate{}

	testCert.CertificateEncoding = 1
	for i := 0; i < 8; i++ {
		partCertificate := make([]byte, 8)
		binary.BigEndian.PutUint64(partCertificate, 4378217432157543265)
		testCert.CertificateData = append(testCert.CertificateData, partCertificate...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testCert)

	testCertReq := &CertificateRequest{}

	testCertReq.CertificateEncoding = 1
	for i := 0; i < 8; i++ {
		partCertificateRquest := make([]byte, 8)
		binary.BigEndian.PutUint64(partCertificateRquest, 7438274381754372584)
		testCertReq.CertificationAuthority = append(testCertReq.CertificationAuthority, partCertificateRquest...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testCertReq)

	testAuth := &Authentication{}

	testAuth.AuthenticationMethod = 1
	for i := 0; i < 8; i++ {
		partAuthentication := make([]byte, 8)
		binary.BigEndian.PutUint64(partAuthentication, 4632714362816473824)
		testAuth.AuthenticationData = append(testAuth.AuthenticationData, partAuthentication...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testAuth)

	testNonce := &Nonce{}

	for i := 0; i < 8; i++ {
		partNonce := make([]byte, 8)
		binary.BigEndian.PutUint64(partNonce, 8984327463782167381)
		testNonce.NonceData = append(testNonce.NonceData, partNonce...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testNonce)

	testNotification := &Notification{}

	testNotification.ProtocolID = 1
	testNotification.NotifyMessageType = 2

	for i := 0; i < 5; i++ {
		partSPI := make([]byte, 8)
		binary.BigEndian.PutUint64(partSPI, 4372847328749832794)
		testNotification.SPI = append(testNotification.SPI, partSPI...)
	}

	for i := 0; i < 19; i++ {
		partNotification := make([]byte, 8)
		binary.BigEndian.PutUint64(partNotification, 9721437148392747354)
		testNotification.NotificationData = append(testNotification.NotificationData, partNotification...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testNotification)

	testDelete := &Delete{}

	testDelete.ProtocolID = 1
	testDelete.SPISize = 9
	testDelete.NumberOfSPI = 4

	for i := 0; i < 36; i++ {
		testDelete.SPIs = append(testDelete.SPIs, 87)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testDelete)

	testVendor := &VendorID{}

	for i := 0; i < 5; i++ {
		partVendorData := make([]byte, 8)
		binary.BigEndian.PutUint64(partVendorData, 5421487329873941748)
		testVendor.VendorIDData = append(testVendor.VendorIDData, partVendorData...)
	}

	testPacket.IKEPayload = append(testPacket.IKEPayload, testVendor)

	testTSi := &TrafficSelectorResponder{}

	testIndividualTS := &IndividualTrafficSelector{}

	testIndividualTS.TSType = 7
	testIndividualTS.IPProtocolID = 6
	testIndividualTS.StartPort = 1989
	testIndividualTS.EndPort = 2020

	testIndividualTS.StartAddress = []byte{192, 168, 0, 15}
	testIndividualTS.EndAddress = []byte{192, 168, 0, 192}

	testTSi.TrafficSelectors = append(testTSi.TrafficSelectors, testIndividualTS)

	testIndividualTS = &IndividualTrafficSelector{}

	testIndividualTS.TSType = 8
	testIndividualTS.IPProtocolID = 6
	testIndividualTS.StartPort = 2010
	testIndividualTS.EndPort = 2050

	testIndividualTS.StartAddress = net.ParseIP("2001:db8::68")
	testIndividualTS.EndAddress = net.ParseIP("2001:db8::72")

	testTSi.TrafficSelectors = append(testTSi.TrafficSelectors, testIndividualTS)

	testPacket.IKEPayload = append(testPacket.IKEPayload, testTSi)

	testCP := new(Configuration)

	testCP.ConfigurationType = 1

	testIndividualConfigurationAttribute := new(IndividualConfigurationAttribute)

	testIndividualConfigurationAttribute.Type = 1
	testIndividualConfigurationAttribute.Value = []byte{10, 1, 14, 1}

	testCP.ConfigurationAttribute = append(testCP.ConfigurationAttribute, testIndividualConfigurationAttribute)

	testPacket.IKEPayload = append(testPacket.IKEPayload, testCP)

	testEAP := new(EAP)

	testEAP.Code = 1
	testEAP.Identifier = 123

	testEAPExpanded := new(EAPExpanded)

	testEAPExpanded.VendorID = 26838
	testEAPExpanded.VendorType = 1
	testEAPExpanded.VendorData = []byte{9, 4, 8, 7}

	testEAPNotification := new(EAPNotification)

	rawstr := "I'm tired"
	testEAPNotification.NotificationData = []byte(rawstr)

	testEAP.EAPTypeData = append(testEAP.EAPTypeData, testEAPNotification)

	testPacket.IKEPayload = append(testPacket.IKEPayload, testEAP)

	testSK := new(Encrypted)

	testSK.NextPayload = TypeSA

	ikePayload := []IKEPayloadType{
		testSA,
		testAuth,
	}

	ikePayloadDataForSK, retErr := EncodePayload(ikePayload)
	if retErr != nil {
		t.Fatalf("EncodePayload failed: %+v", retErr)
	}

	// aes 128 key
	key, retErr := hex.DecodeString("6368616e676520746869732070617373")
	if retErr != nil {
		t.Fatalf("HexDecoding failed: %+v", retErr)
	}
	block, retErr := aes.NewCipher(key)
	if retErr != nil {
		t.Fatalf("AES NewCipher failed: %+v", retErr)
	}

	// padding plaintext
	padNum := len(ikePayloadDataForSK) % aes.BlockSize
	for i := 0; i < (aes.BlockSize - padNum); i++ {
		ikePayloadDataForSK = append(ikePayloadDataForSK, byte(padNum))
	}

	// ciphertext
	cipherText := make([]byte, aes.BlockSize+len(ikePayloadDataForSK))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(Crand.Reader, iv); err != nil {
		t.Fatalf("IO ReadFull failed: %+v", err)
	}

	// CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], ikePayloadDataForSK)

	testSK.EncryptedData = cipherText

	testPacket.IKEPayload = append(testPacket.IKEPayload, testSK)

	var data1, data2 []byte
	var err error
	var resultPacket *IKEMessage

	if data1, err = Encode(testPacket); err != nil {
		t.Fatalf("Encode failed: %+v", err)
	}

	t.Logf("%+v", data1)

	if resultPacket, err = Decode(data1); err != nil {
		t.Fatalf("Decode failed: %+v", err)
	}

	if data2, err = Encode(resultPacket); err != nil {
		t.Fatalf("Encode failed: %+v", err)
	}

	t.Logf("Original IKE Message: %+v", data1)
	t.Logf("Result IKE Message: %+v", data2)

	_, err = conn.Write(data1)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}

	t.FailNow()

}
