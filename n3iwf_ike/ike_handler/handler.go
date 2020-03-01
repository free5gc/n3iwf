package ike_handler

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"net"
	"strings"

	"gofree5gc/src/n3iwf/logger"
	"gofree5gc/src/n3iwf/n3iwf_context"
	"gofree5gc/src/n3iwf/n3iwf_handler/n3iwf_message"
	"gofree5gc/src/n3iwf/n3iwf_ike/ike_message"
	"gofree5gc/src/n3iwf/n3iwf_ngap/ngap_message"

	"github.com/sirupsen/logrus"
)

// Log
var ikeLog *logrus.Entry

func init() {
	ikeLog = logger.IKELog
}

func HandleIKESAINIT(ueSendInfo *n3iwf_message.UDPSendInfoGroup, message *ike_message.IKEMessage) {
	ikeLog.Infoln("[IKE] Handle IKE_SA_INIT")

	var securityAssociation *ike_message.SecurityAssociation
	var keyExcahge *ike_message.KeyExchange
	var nonce *ike_message.Nonce

	n3iwfSelf := n3iwf_context.N3IWFSelf()

	var responseIKEMessage *ike_message.IKEMessage
	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseKeyExchange *ike_message.KeyExchange
	var responseNonce *ike_message.Nonce

	var sharedKeyData, concatenatedNonce []byte

	if message == nil {
		ikeLog.Error("[IKE] IKE Message is nil")
		return
	}

	// parse IKE header and setup IKE context
	// check major version
	majorVersion := ((message.Version & 0xf0) >> 4)
	if majorVersion > 2 {
		ikeLog.Warn("[IKE] Received an IKE message with higher major version")
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload
		responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.INFORMATIONAL, ike_message.ResponseBitCheck, message.MessageID)
		notificationPayload := ike_message.BuildNotification(ike_message.TypeNone, ike_message.INVALID_MAJOR_VERSION, nil, nil)

		responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, notificationPayload)

		ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)

		return
	}

	for _, ikePayload := range message.IKEPayload {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			securityAssociation = ikePayload.(*ike_message.SecurityAssociation)
		case ike_message.TypeKE:
			keyExcahge = ikePayload.(*ike_message.KeyExchange)
		case ike_message.TypeN:
			nonce = ikePayload.(*ike_message.Nonce)
		default:
			ikeLog.Warnf("[IKE] Get IKE payload (type %d) in IKE_SA_INIT message, this payload will not be handled by IKE handler")
		}
	}

	if securityAssociation != nil {
		for _, proposal := range securityAssociation.Proposals {
			chosenProposal := new(ike_message.Proposal)

			if len(proposal.EncryptionAlgorithm) > 0 {
				for _, transform := range proposal.EncryptionAlgorithm {
					if is_supported(ike_message.TypeEncryptionAlgorithm, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
						chosenProposal.EncryptionAlgorithm = append(chosenProposal.EncryptionAlgorithm, transform)
						break
					}
				}
				if len(chosenProposal.EncryptionAlgorithm) == 0 {
					continue
				}
			} else {
				continue
			}
			if len(proposal.PseudorandomFunction) > 0 {
				for _, transform := range proposal.PseudorandomFunction {
					if is_supported(ike_message.TypePseudorandomFunction, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
						chosenProposal.PseudorandomFunction = append(chosenProposal.PseudorandomFunction, transform)
						break
					}
				}
				if len(chosenProposal.PseudorandomFunction) == 0 {
					continue
				}
			} else {
				continue
			}
			if len(proposal.IntegrityAlgorithm) > 0 {
				for _, transform := range proposal.IntegrityAlgorithm {
					if is_supported(ike_message.TypeIntegrityAlgorithm, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
						chosenProposal.IntegrityAlgorithm = append(chosenProposal.IntegrityAlgorithm, transform)
						break
					}
				}
				if len(chosenProposal.IntegrityAlgorithm) == 0 {
					continue
				}
			} else {
				continue
			}
			if len(proposal.DiffieHellmanGroup) > 0 {
				for _, transform := range proposal.DiffieHellmanGroup {
					if is_supported(ike_message.TypeDiffieHellmanGroup, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
						chosenProposal.DiffieHellmanGroup = append(chosenProposal.DiffieHellmanGroup, transform)
						break
					}
				}
				if len(chosenProposal.DiffieHellmanGroup) == 0 {
					continue
				}
			} else {
				continue
			}
			if len(proposal.ExtendedSequenceNumbers) > 0 {
				for _, transform := range proposal.ExtendedSequenceNumbers {
					if is_supported(ike_message.TypeExtendedSequenceNumbers, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
						chosenProposal.ExtendedSequenceNumbers = append(chosenProposal.ExtendedSequenceNumbers, transform)
						break
					}
				}
				if len(chosenProposal.ExtendedSequenceNumbers) == 0 {
					continue
				}
			}

			chosenProposal.ProposalNumber = proposal.ProposalNumber
			chosenProposal.ProtocolID = proposal.ProtocolID

			responseSecurityAssociation = &ike_message.SecurityAssociation{
				Proposals: []*ike_message.Proposal{
					chosenProposal,
				},
			}

			break
		}

		if responseSecurityAssociation == nil {
			ikeLog.Warn("[IKE] No proposal chosen")
			// Respond NO_PROPOSAL_CHOSEN to UE
			responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_SA_INIT, ike_message.ResponseBitCheck, message.MessageID)
			notificationPayload := ike_message.BuildNotification(ike_message.TypeNone, ike_message.NO_PROPOSAL_CHOSEN, nil, nil)

			responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, notificationPayload)

			ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)

			return
		}
	} else {
		ikeLog.Error("[IKE] The security association field is nil")
		// TODO: send error message to UE
		return
	}

	if keyExcahge != nil {
		chosenDiffieHellmanGroup := responseSecurityAssociation.Proposals[0].DiffieHellmanGroup[0].TransformID
		if chosenDiffieHellmanGroup != keyExcahge.DiffieHellmanGroup {
			ikeLog.Warn("[IKE] The Diffie-Hellman group defined in key exchange payload not matches the one in chosen proposal")
			// send INVALID_KE_PAYLOAD to UE
			responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_SA_INIT, ike_message.ResponseBitCheck, message.MessageID)

			notificationData := make([]byte, 2)
			binary.BigEndian.PutUint16(notificationData, chosenDiffieHellmanGroup)

			notificationPayload := ike_message.BuildNotification(ike_message.TypeNone, ike_message.INVALID_KE_PAYLOAD, nil, notificationData)

			responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, notificationPayload)

			ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)

			return
		}

		var localPublicValue []byte

		localPublicValue, sharedKeyData = CalculateDiffieHellmanMaterials(GenerateRandomNumber(), keyExcahge.KeyExchangeData, chosenDiffieHellmanGroup)
		responseKeyExchange = &ike_message.KeyExchange{
			DiffieHellmanGroup: chosenDiffieHellmanGroup,
			KeyExchangeData:    localPublicValue,
		}
	} else {
		ikeLog.Error("[IKE] The key exchange field is nil")
		// TODO: send error message to UE
		return
	}

	if nonce != nil {
		localNonce := GenerateRandomNumber().Bytes()
		concatenatedNonce = append(nonce.NonceData, localNonce...)

		responseNonce = &ike_message.Nonce{
			NonceData: localNonce,
		}
	} else {
		ikeLog.Error("[IKE] The nonce field is nil")
		// TODO: send error message to UE
		return
	}

	// Create new IKE security association
	ikeSecurityAssociation := n3iwfSelf.NewIKESecurityAssociation()
	ikeSecurityAssociation.RemoteSPI = message.InitiatorSPI

	// Record algorithm in context
	ikeSecurityAssociation.EncryptionAlgorithm = responseSecurityAssociation.Proposals[0].EncryptionAlgorithm[0]
	ikeSecurityAssociation.IntegrityAlgorithm = responseSecurityAssociation.Proposals[0].IntegrityAlgorithm[0]
	ikeSecurityAssociation.PseudorandomFunction = responseSecurityAssociation.Proposals[0].PseudorandomFunction[0]
	ikeSecurityAssociation.DiffieHellmanGroup = responseSecurityAssociation.Proposals[0].DiffieHellmanGroup[0]

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int
	var ok bool

	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction

	if length_SK_d, ok = getKeyLength(transformPseudorandomFunction.TransformType, transformPseudorandomFunction.TransformID, transformPseudorandomFunction.AttributePresent, transformPseudorandomFunction.AttributeValue); !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return
	}
	if length_SK_ai, ok = getKeyLength(transformIntegrityAlgorithm.TransformType, transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent, transformIntegrityAlgorithm.AttributeValue); !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return
	}
	length_SK_ar = length_SK_ai
	if length_SK_ei, ok = getKeyLength(transformEncryptionAlgorithm.TransformType, transformEncryptionAlgorithm.TransformID, transformEncryptionAlgorithm.AttributePresent, transformEncryptionAlgorithm.AttributeValue); !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return
	}
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = NewPseudorandomFunction(concatenatedNonce, transformPseudorandomFunction.TransformID); !ok {
		ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return
	}
	pseudorandomFunction.Write(sharedKeyData)

	SKEYSEED := pseudorandomFunction.Sum(nil)
	seed := concatenateNonceAndSPI(concatenatedNonce, ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return
		}
		pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index))
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	ikeSecurityAssociation.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	ikeSecurityAssociation.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	ikeSecurityAssociation.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	ikeSecurityAssociation.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	ikeSecurityAssociation.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	ikeSecurityAssociation.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	ikeSecurityAssociation.SK_pr = keyStream[:length_SK_pr]
	keyStream = keyStream[length_SK_pr:]

	// Send response to UE
	responseIKEMessage = ike_message.BuildIKEHeader(ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI, ike_message.IKE_SA_INIT, ike_message.ResponseBitCheck, message.MessageID)
	responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseSecurityAssociation)
	responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseKeyExchange)
	responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseNonce)

	// Prepare authentication data
	// Record received message and nonce for IKE_AUTH authentication
	receivedIKEMessageData, err := ike_message.Encode(message)
	if err != nil {
		ikeLog.Errorln(err)
		ikeLog.Error("[IKE] Encode message failed.")
		return
	}
	ikeSecurityAssociation.RemoteUnsignedAuthentication = append(receivedIKEMessageData, responseNonce.NonceData...)

	// Record response message and nonce and maced identification for IKE_AUTH authentication
	responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
	if err != nil {
		ikeLog.Errorln(err)
		ikeLog.Error("[IKE] Encoding IKE message failed")
		return
	}
	ikeSecurityAssociation.LocalUnsignedAuthentication = append(responseIKEMessageData, nonce.NonceData...)

	idPayload := []ike_message.IKEPayloadType{
		ike_message.BuildIdentificationResponder(ike_message.ID_FQDN, []byte(n3iwfSelf.FQDN)),
	}
	idPayloadData, err := ike_message.EncodePayload(idPayload)
	if err != nil {
		ikeLog.Errorln(err)
		ikeLog.Error("[IKE] Encode IKE payload failed.")
		return
	}
	if pseudorandomFunction, ok = NewPseudorandomFunction(ikeSecurityAssociation.SK_pr, transformPseudorandomFunction.TransformID); !ok {
		ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return
	}
	pseudorandomFunction.Write(idPayloadData[4:])
	ikeSecurityAssociation.LocalUnsignedAuthentication = append(ikeSecurityAssociation.LocalUnsignedAuthentication, pseudorandomFunction.Sum(nil)...)

	ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)
}

// IKE_AUTH state
const (
	PreSignalling = iota + 1
	EAPSignalling
	PostSignalling
)

func HandleIKEAUTH(ueSendInfo *n3iwf_message.UDPSendInfoGroup, message *ike_message.IKEMessage) {
	ikeLog.Infoln("[IKE] Handle IKE_AUTH")

	var encryptedPayload *ike_message.Encrypted

	n3iwfSelf := n3iwf_context.N3IWFSelf()

	// {response}
	var responseIKEMessage *ike_message.IKEMessage

	if message == nil {
		ikeLog.Error("[IKE] IKE Message is nil")
		return
	}

	// parse IKE header and setup IKE context
	// check major version
	majorVersion := ((message.Version & 0xf0) >> 4)
	if majorVersion > 2 {
		ikeLog.Warn("[IKE] Received an IKE message with higher major version")
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload ( OUTSIDE IKE SA )

		// IKEHDR-{response}
		responseNotification := ike_message.BuildNotification(ike_message.TypeNone, ike_message.INVALID_MAJOR_VERSION, nil, nil)

		responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.INFORMATIONAL, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseNotification)

		ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)

		return
	}

	// Find corresponding IKE security association
	localSPI := message.ResponderSPI
	ikeSecurityAssociation := n3iwfSelf.FindIKESecurityAssociationBySPI(localSPI)
	if ikeSecurityAssociation == nil {
		ikeLog.Warn("[IKE] Unrecognized SPI")
		// send INFORMATIONAL type message with INVALID_IKE_SPI Notify payload ( OUTSIDE IKE SA )

		// IKEHDR-{response}
		responseNotification := ike_message.BuildNotification(ike_message.TypeNone, ike_message.INVALID_IKE_SPI, nil, nil)

		responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, 0, ike_message.INFORMATIONAL, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseNotification)

		ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)

		return
	}

	for _, ikePayload := range message.IKEPayload {
		switch ikePayload.Type() {
		case ike_message.TypeSK:
			encryptedPayload = ikePayload.(*ike_message.Encrypted)
		default:
			ikeLog.Warnf("[IKE] Get IKE payload (type %d) in IKE_SA_INIT message, this payload will not be handled by IKE handler")
		}
	}

	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction
	integrityKeyLength, ok := getKeyLength(transformIntegrityAlgorithm.TransformType, transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent, transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return
	}

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-integrityKeyLength:]

	ikeMessageData, err := ike_message.Encode(message)
	if err != nil {
		ikeLog.Errorln(err)
		ikeLog.Error("Error occur when encoding for checksum")
		return
	}

	ok, err = VerifyIKEChecksum(ikeSecurityAssociation.SK_ai, ikeMessageData[:len(ikeMessageData)-integrityKeyLength], checksum, transformIntegrityAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("[IKE] Error occur when verifying checksum: %+v", err)
		return
	}
	if !ok {
		ikeLog.Warn("[IKE] Message checksum failed. Drop the message.")
		return
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-integrityKeyLength]
	plainText, err := DecryptMessage(ikeSecurityAssociation.SK_ei, encryptedData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("[IKE] Error occur when decrypting message: %+v", err)
		return
	}

	decryptedIKEPayload, err := ike_message.DecodePayload(encryptedPayload.NextPayload, plainText)
	if err != nil {
		ikeLog.Errorln(err)
		ikeLog.Error("[IKE] Decoding decrypted payload failed.")
		return
	}

	// Parse payloads
	var initiatorID *ike_message.IdentificationInitiator
	var certificateRequest *ike_message.CertificateRequest
	var certificate *ike_message.Certificate
	var securityAssociation *ike_message.SecurityAssociation
	var trafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var trafficSelectorResponder *ike_message.TrafficSelectorResponder
	var eap *ike_message.EAP
	var authentication *ike_message.Authentication
	var configuration *ike_message.Configuration

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case ike_message.TypeIDi:
			initiatorID = ikePayload.(*ike_message.IdentificationInitiator)
		case ike_message.TypeCERTreq:
			certificateRequest = ikePayload.(*ike_message.CertificateRequest)
		case ike_message.TypeCERT:
			certificate = ikePayload.(*ike_message.Certificate)
		case ike_message.TypeSA:
			securityAssociation = ikePayload.(*ike_message.SecurityAssociation)
		case ike_message.TypeTSi:
			trafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			trafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeEAP:
			eap = ikePayload.(*ike_message.EAP)
		case ike_message.TypeAUTH:
			authentication = ikePayload.(*ike_message.Authentication)
		case ike_message.TypeCP:
			configuration = ikePayload.(*ike_message.Configuration)
		default:
			ikeLog.Warnf("[IKE] Get IKE payload (type %d) in IKE_AUTH message, this payload will not be handled by IKE handler")
		}
	}

	switch ikeSecurityAssociation.State {
	case PreSignalling:
		// IKEHDR-{response}
		var responseEncryptedPayload *ike_message.Encrypted
		// IKEHDR-SK-{response}
		var responseIdentification *ike_message.IdentificationResponder
		var responseCertificate *ike_message.Certificate
		var responseAuthentication *ike_message.Authentication
		var requestEAPPayload *ike_message.EAP

		if initiatorID != nil {
			ikeSecurityAssociation.InitiatorID = initiatorID

			// Record maced identification for authentication
			idPayload := []ike_message.IKEPayloadType{
				initiatorID,
			}
			idPayloadData, err := ike_message.EncodePayload(idPayload)
			if err != nil {
				ikeLog.Errorln(err)
				ikeLog.Error("[IKE] Encoding ID payload message failed.")
				return
			}
			pseudorandomFunction, ok := NewPseudorandomFunction(ikeSecurityAssociation.SK_pr, transformPseudorandomFunction.TransformID)
			if !ok {
				ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
				return
			}
			pseudorandomFunction.Write(idPayloadData[4:])
			ikeSecurityAssociation.RemoteUnsignedAuthentication = append(ikeSecurityAssociation.RemoteUnsignedAuthentication, pseudorandomFunction.Sum(nil)...)
		} else {
			ikeLog.Error("[IKE] The initiator identification field is nil")
			// TODO: send error message to UE
			return
		}

		// Certificate request and prepare coresponding certificate
		if certificateRequest != nil {
			if CompareRootCertificate(certificateRequest.CertificationAuthority, certificateRequest.CertificateEncoding) {
				responseCertificate = ike_message.BuildCertificate(ike_message.X509CertificateSignature, n3iwfSelf.N3IWFCertificate)
			}
		}

		if certificate != nil {
			ikeSecurityAssociation.InitiatorCertificate = certificate
		}

		if securityAssociation != nil {
			var chosenSecurityAssociation *ike_message.SecurityAssociation

			for _, proposal := range securityAssociation.Proposals {
				chosenProposal := new(ike_message.Proposal)

				if len(proposal.EncryptionAlgorithm) > 0 {
					for _, transform := range proposal.EncryptionAlgorithm {
						if is_supported(ike_message.TypeEncryptionAlgorithm, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
							chosenProposal.EncryptionAlgorithm = append(chosenProposal.EncryptionAlgorithm, transform)
							break
						}
					}
					if len(chosenProposal.EncryptionAlgorithm) == 0 {
						continue
					}
				} else {
					continue
				}
				if len(proposal.PseudorandomFunction) > 0 {
					for _, transform := range proposal.PseudorandomFunction {
						if is_supported(ike_message.TypePseudorandomFunction, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
							chosenProposal.PseudorandomFunction = append(chosenProposal.PseudorandomFunction, transform)
							break
						}
					}
					if len(chosenProposal.PseudorandomFunction) == 0 {
						continue
					}
				} else {
					continue
				}
				if len(proposal.IntegrityAlgorithm) > 0 {
					for _, transform := range proposal.IntegrityAlgorithm {
						if is_supported(ike_message.TypeIntegrityAlgorithm, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
							chosenProposal.IntegrityAlgorithm = append(chosenProposal.IntegrityAlgorithm, transform)
							break
						}
					}
					if len(chosenProposal.IntegrityAlgorithm) == 0 {
						continue
					}
				} else {
					continue
				}
				if len(proposal.DiffieHellmanGroup) > 0 {
					for _, transform := range proposal.DiffieHellmanGroup {
						if is_supported(ike_message.TypeDiffieHellmanGroup, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
							chosenProposal.DiffieHellmanGroup = append(chosenProposal.DiffieHellmanGroup, transform)
							break
						}
					}
					if len(chosenProposal.DiffieHellmanGroup) == 0 {
						continue
					}
				} else {
					continue
				}
				if len(proposal.ExtendedSequenceNumbers) > 0 {
					for _, transform := range proposal.ExtendedSequenceNumbers {
						if is_supported(ike_message.TypeExtendedSequenceNumbers, transform.TransformID, transform.AttributePresent, transform.AttributeValue) {
							chosenProposal.ExtendedSequenceNumbers = append(chosenProposal.ExtendedSequenceNumbers, transform)
							break
						}
					}
					if len(chosenProposal.ExtendedSequenceNumbers) == 0 {
						continue
					}
				}

				chosenProposal.ProposalNumber = proposal.ProposalNumber
				chosenProposal.ProtocolID = proposal.ProtocolID
				chosenProposal.SPI = append(chosenProposal.SPI, proposal.SPI...)

				chosenSecurityAssociation = &ike_message.SecurityAssociation{
					Proposals: []*ike_message.Proposal{
						chosenProposal,
					},
				}

				break
			}

			if chosenSecurityAssociation == nil {
				ikeLog.Warn("[IKE] No proposal chosen")
				// Respond NO_PROPOSAL_CHOSEN to UE
				var ikePayload []ike_message.IKEPayloadType

				// Notification
				notificationPayload := ike_message.BuildNotification(ike_message.TypeNone, ike_message.NO_PROPOSAL_CHOSEN, nil, nil)
				ikePayload = append(ikePayload, notificationPayload)

				// Encrypting
				notificationPayloadData, err := ike_message.EncodePayload(ikePayload)
				if err != nil {
					ikeLog.Error(err)
					ikeLog.Error("[IKE] Encode IKE payload failed.")
					return
				}

				encryptedData, err := EncryptMessage(ikeSecurityAssociation.SK_er, notificationPayloadData, transformEncryptionAlgorithm.TransformID)
				if err != nil {
					ikeLog.Errorf("[IKE] Encrypting data error: %+v", err)
					return
				}

				encryptedData = append(encryptedData, make([]byte, integrityKeyLength)...)
				responseEncryptedPayload := ike_message.BuildEncryptedPayload(ike_message.TypeN, encryptedData)

				// Build IKE message
				responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
				responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

				// Calculate checksum
				responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
				if err != nil {
					ikeLog.Error(err)
					ikeLog.Error("[IKE] Encoding IKE message error")
					return
				}
				checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar, responseIKEMessageData[:len(responseIKEMessageData)-integrityKeyLength], transformIntegrityAlgorithm.TransformID)
				if err != nil {
					ikeLog.Errorf("[IKE] Calculating checksum failed: %+v", err)
					return
				}
				checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-integrityKeyLength:]
				copy(checksumField, checksumOfMessage)

				// Send IKE message to UE
				ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)

				return
			}

			ikeSecurityAssociation.IKEAuthResponseSA = chosenSecurityAssociation
		} else {
			ikeLog.Error("[IKE] The security association field is nil")
			// TODO: send error message to UE
			return
		}

		if trafficSelectorInitiator != nil {
			ikeSecurityAssociation.TrafficSelectorInitiator = trafficSelectorInitiator
		} else {
			ikeLog.Error("[IKE] The initiator traffic selector field is nil")
			// TODO: send error message to UE
			return
		}

		if trafficSelectorResponder != nil {
			ikeSecurityAssociation.TrafficSelectorResponder = trafficSelectorResponder
		} else {
			ikeLog.Error("[IKE] The initiator traffic selector field is nil")
			// TODO: send error message to UE
			return
		}

		// Build response
		var ikePayload []ike_message.IKEPayloadType

		// Identification
		responseIdentification = ike_message.BuildIdentificationResponder(ike_message.ID_FQDN, []byte(n3iwfSelf.FQDN))
		ikePayload = append(ikePayload, responseIdentification)

		// Certificate
		if responseCertificate == nil {
			responseCertificate = ike_message.BuildCertificate(ike_message.X509CertificateSignature, n3iwfSelf.N3IWFCertificate)
		}
		ikePayload = append(ikePayload, responseCertificate)

		// Authentication Data
		sha1HashFunction := sha1.New()
		sha1HashFunction.Write(ikeSecurityAssociation.LocalUnsignedAuthentication)

		signedAuth, err := rsa.SignPKCS1v15(rand.Reader, n3iwfSelf.N3IWFPrivateKey, crypto.SHA1, sha1HashFunction.Sum(nil))
		if err != nil {
			ikeLog.Errorf("[IKE] Sign authentication data failed: %+v", err)
		}

		responseAuthentication = ike_message.BuildAuthentication(ike_message.RSADigitalSignature, signedAuth)
		ikePayload = append(ikePayload, responseAuthentication)

		// EAP expanded 5G-Start
		var identifier uint8
		for {
			identifier, err = GenerateRandomUint8()
			if err != nil {
				ikeLog.Errorf("[IKE] Random number failed: %+v", err)
				return
			}
			if identifier != ikeSecurityAssociation.LastEAPIdentifier {
				break
			}
		}
		requestEAPPayload = &ike_message.EAP{
			Code:       ike_message.EAPCodeRequest,
			Identifier: identifier,
			EAPTypeData: []ike_message.EAPTypeFormat{
				&ike_message.EAPExpanded{
					VendorID:   VendorID3GPP,
					VendorType: VendorTypeEAP5G,
					VendorData: BuildEAP5GStart(),
				},
			},
		}
		ikePayload = append(ikePayload, requestEAPPayload)

		// Encrypting
		ikePayloadData, err := ike_message.EncodePayload(ikePayload)
		if err != nil {
			ikeLog.Errorln(err)
			ikeLog.Error("[IKE] Encode payload failed.")
			return
		}
		encryptedIKEPayloadData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData, transformEncryptionAlgorithm.TransformID)
		if err != nil {
			ikeLog.Errorf("[IKE] Encrypting message failed: %+v", err)
			return
		}
		encryptedIKEPayloadData = append(encryptedIKEPayloadData, make([]byte, integrityKeyLength)...)
		responseEncryptedPayload = ike_message.BuildEncryptedPayload(ike_message.TypeIDr, encryptedIKEPayloadData)

		// Build IKE message
		responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

		// Calculate checksum
		responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
		if err != nil {
			ikeLog.Errorln(err)
			ikeLog.Error("[IKE] Encode message failed.")
			return
		}
		checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar, responseIKEMessageData[:len(responseIKEMessageData)-integrityKeyLength], transformIntegrityAlgorithm.TransformID)
		if err != nil {
			ikeLog.Errorf("[IKE] Calculating checksum failed: %+v", err)
			return
		}
		checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-integrityKeyLength:]
		copy(checksumField, checksumOfMessage)

		// Send IKE message to UE
		ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)

	case EAPSignalling:
		// IKEHDR-{response}
		var responseEncryptedPayload *ike_message.Encrypted
		// IKEHDR-SK-{response}
		var responseEAP *ike_message.EAP

		if eap != nil {
			if eap.Code != ike_message.EAPCodeResponse {
				ikeLog.Error("[IKE][EAP] Received an EAP payload with code other than response. Drop the payload.")
				return
			}
			if eap.Identifier != ikeSecurityAssociation.LastEAPIdentifier {
				ikeLog.Error("[IKE][EAP] Received an EAP payload with unmatched identifier. Drop the payload.")
				return
			}

			eapTypeData := eap.EAPTypeData[0]
			var eapExpanded *ike_message.EAPExpanded

			switch eapTypeData.Type() {
			// TODO: handle
			// case ike_message.EAPTypeIdentity:
			// case ike_message.EAPTypeNotification:
			// case ike_message.EAPTypeNak:
			case ike_message.EAPTypeExpanded:
				eapExpanded = eapTypeData.(*ike_message.EAPExpanded)
			default:
				ikeLog.Error("[IKE][EAP] Received EAP packet with type other than EAP expanded type: %d", eapTypeData.Type())
				return
			}

			if eapExpanded.VendorID != VendorID3GPP {
				ikeLog.Error("[IKE] The peer sent EAP expended packet with wrong vendor ID. Drop the packet.")
				return
			}

			if eapExpanded.VendorType != VendorTypeEAP5G {
				ikeLog.Error("[IKE] The peer sent EAP expanded packet with wrong vendor type. Drop the packet.")
				return
			}

			eap5GMessageID, anParameters, nasPDU, err := UnmarshalEAP5GData(eapExpanded.VendorData)
			if err != nil {
				ikeLog.Error("[IKE] Unmarshalling EAP-5G packet failed: %+v", err)
				return
			}

			if eap5GMessageID == EAP5GType5GStop {
				// Send EAP failure
				identifier, err := GenerateRandomUint8()
				if err != nil {
					ikeLog.Error("[IKE] Generate random uint8 failed: %+v", err)
					return
				}

				// Build response
				var ikePayload []ike_message.IKEPayloadType

				// EAP
				responseEAP = ike_message.BuildEAPfailure(identifier)
				ikePayload = append(ikePayload, responseEAP)

				// Encrypting
				ikePayloadData, err := ike_message.EncodePayload(ikePayload)
				if err != nil {
					ikeLog.Errorln(err)
					ikeLog.Error("[IKE] Encode payload failed.")
					return
				}
				encryptedIKEPayloadData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData, transformEncryptionAlgorithm.TransformID)
				if err != nil {
					ikeLog.Errorf("[IKE] Encrypting message failed: %+v", err)
					return
				}
				encryptedIKEPayloadData = append(encryptedIKEPayloadData, make([]byte, integrityKeyLength)...)
				responseEncryptedPayload = ike_message.BuildEncryptedPayload(ike_message.TypeIDr, encryptedIKEPayloadData)

				// Build IKE message
				responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
				responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

				// Calculate checksum
				responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
				if err != nil {
					ikeLog.Errorln(err)
					ikeLog.Error("[IKE] Encode message failed.")
					return
				}
				checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar, responseIKEMessageData[:len(responseIKEMessageData)-integrityKeyLength], transformIntegrityAlgorithm.TransformID)
				if err != nil {
					ikeLog.Errorf("[IKE] Calculating checksum failed: %+v", err)
					return
				}
				checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-integrityKeyLength:]
				copy(checksumField, checksumOfMessage)

				// Send IKE message to UE
				ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)
				return
			}

			// Send Initial UE Message or Uplink NAS Transport
			if anParameters != nil {
				// AMF selection
				selectedAMF := n3iwfSelf.AMFSelection(anParameters.GUAMI)
				if selectedAMF == nil {
					ikeLog.Warn("[IKE] No avalible AMF for this UE")
					return
				}
				// Create UE context
				thisUE := n3iwfSelf.NewN3iwfUe()
				// Relative context
				ikeSecurityAssociation.ThisUE = thisUE
				thisUE.N3IWFIKESecurityAssociation = ikeSecurityAssociation
				thisUE.AMF = selectedAMF

				// Store some information in conext
				networkAddrStringSlice := strings.Split(ueSendInfo.Addr.String(), ":")
				thisUE.IPAddrv4 = networkAddrStringSlice[0]
				thisUE.PortNumber = int32(ueSendInfo.Addr.Port)
				thisUE.RRCEstablishmentCause = int16(anParameters.EstablishmentCause.Value)

				// Send Initial UE Message
				ngap_message.SendInitialUEMessage(selectedAMF, thisUE, nasPDU)
			} else {
				thisUE := ikeSecurityAssociation.ThisUE
				amf := thisUE.AMF
				// Send Uplink NAS Transport
				ngap_message.SendUplinkNASTransport(amf, thisUE, nasPDU)
			}
		}

	case PostSignalling:
		// Load needed information
		thisUE := ikeSecurityAssociation.ThisUE

		// IKEHDR-{response}
		var responseEncryptedPayload *ike_message.Encrypted
		// IKEHDR-SK-{response}
		var responseConfiguration *ike_message.Configuration
		var responseAuthentication *ike_message.Authentication
		var responseSecurityAssociation *ike_message.SecurityAssociation
		var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
		var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder

		if authentication != nil {
			// Verifying remote AUTH
			pseudorandomFunction, ok := NewPseudorandomFunction(thisUE.Kn3iwf, transformPseudorandomFunction.TransformID)
			if !ok {
				ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
				return
			}
			pseudorandomFunction.Write([]byte("Key Pad for IKEv2"))
			secret := pseudorandomFunction.Sum(nil)
			pseudorandomFunction, ok = NewPseudorandomFunction(secret, transformPseudorandomFunction.TransformID)
			if !ok {
				ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
				return
			}
			pseudorandomFunction.Write(ikeSecurityAssociation.RemoteUnsignedAuthentication)
			expectedAuthenticationData := pseudorandomFunction.Sum(nil)

			if !bytes.Equal(authentication.AuthenticationData, expectedAuthenticationData) {
				ikeLog.Warn("[IKE] Peer authentication failed.")
				// Inform UE the authentication has failed
				// IKEHDR-SK-{response}
				var notification *ike_message.Notification

				// Build response
				var ikePayload []ike_message.IKEPayloadType

				// Notification
				notification = ike_message.BuildNotification(ike_message.TypeNone, ike_message.AUTHENTICATION_FAILED, nil, nil)
				ikePayload = append(ikePayload, notification)

				// Encrypting
				ikePayloadData, err := ike_message.EncodePayload(ikePayload)
				if err != nil {
					ikeLog.Errorln(err)
					ikeLog.Error("[IKE] Encode payload failed.")
					return
				}
				encryptedIKEPayloadData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData, transformEncryptionAlgorithm.TransformID)
				if err != nil {
					ikeLog.Errorf("[IKE] Encrypting message failed: %+v", err)
					return
				}
				encryptedIKEPayloadData = append(encryptedIKEPayloadData, make([]byte, integrityKeyLength)...)
				responseEncryptedPayload = ike_message.BuildEncryptedPayload(ike_message.TypeIDr, encryptedIKEPayloadData)

				// Build IKE message
				responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
				responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

				// Calculate checksum
				responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
				if err != nil {
					ikeLog.Errorln(err)
					ikeLog.Error("[IKE] Encode message failed.")
					return
				}
				checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar, responseIKEMessageData[:len(responseIKEMessageData)-integrityKeyLength], transformIntegrityAlgorithm.TransformID)
				if err != nil {
					ikeLog.Errorf("[IKE] Calculating checksum failed: %+v", err)
					return
				}
				checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-integrityKeyLength:]
				copy(checksumField, checksumOfMessage)

				// Send IKE message to UE
				ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)
				return
			}
		} else {
			ikeLog.Warn("[IKE] Peer authentication failed.")
			// Inform UE the authentication has failed
			// IKEHDR-SK-{response}
			var responseNotification *ike_message.Notification

			// Build response
			var ikePayload []ike_message.IKEPayloadType

			// Notification
			responseNotification = ike_message.BuildNotification(ike_message.TypeNone, ike_message.AUTHENTICATION_FAILED, nil, nil)
			ikePayload = append(ikePayload, responseNotification)

			// Encrypting
			ikePayloadData, err := ike_message.EncodePayload(ikePayload)
			if err != nil {
				ikeLog.Errorln(err)
				ikeLog.Error("[IKE] Encode payload failed.")
				return
			}
			encryptedIKEPayloadData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData, transformEncryptionAlgorithm.TransformID)
			if err != nil {
				ikeLog.Errorf("[IKE] Encrypting message failed: %+v", err)
				return
			}
			encryptedIKEPayloadData = append(encryptedIKEPayloadData, make([]byte, integrityKeyLength)...)
			responseEncryptedPayload = ike_message.BuildEncryptedPayload(ike_message.TypeIDr, encryptedIKEPayloadData)

			// Build IKE message
			responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
			responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

			// Calculate checksum
			responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
			if err != nil {
				ikeLog.Errorln(err)
				ikeLog.Error("[IKE] Encode message failed.")
				return
			}
			checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar, responseIKEMessageData[:len(responseIKEMessageData)-integrityKeyLength], transformIntegrityAlgorithm.TransformID)
			if err != nil {
				ikeLog.Errorf("[IKE] Calculating checksum failed: %+v", err)
				return
			}
			checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-integrityKeyLength:]
			copy(checksumField, checksumOfMessage)

			// Send IKE message to UE
			ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)
			return
		}

		// Parse configuration request to get the number of internal address UE has requested,
		// and prepare configuration payload to UE
		var addrRequestNumber int

		if configuration != nil {
			ikeLog.Tracef("[IKE] Received configuration payload with type: %d", configuration.ConfigurationType)

			var attribute *ike_message.IndividualConfigurationAttribute
			for _, attribute = range configuration.ConfigurationAttribute {
				switch attribute.Type {
				case ike_message.INTERNAL_IP4_ADDRESS:
					addrRequestNumber++
					if len(attribute.Value) != 0 {
						ikeLog.Tracef("[IKE] Got client requested address: %d.%d.%d.%d", attribute.Value[0], attribute.Value[1], attribute.Value[2], attribute.Value[3])
					}
				default:
					ikeLog.Warn("[IKE] Receive other type of configuration request: %d", attribute.Type)
				}
			}
		} else {
			ikeLog.Warn("[IKE] Configuration is nil. UE did not sent any configuration request.")
		}

		// Prepare configuration payload and traffic selector payload for initiator and responder
		if addrRequestNumber != 0 {
			var attributes []*ike_message.IndividualConfigurationAttribute
			var ueIPAddr net.IP

			if addrRequestNumber == 1 {
				// UE internal IP address
				for {
					ueIPAddr = GenRandomIPinRange(n3iwfSelf.Subnet)
					if ueIPAddr != nil {
						if _, ok := n3iwfSelf.AllocatedUEIPAddress[ueIPAddr.String()]; !ok {
							// Should be release if there is any error occur
							n3iwfSelf.AllocatedUEIPAddress[ueIPAddr.String()] = thisUE
							break
						}
					}
				}
				attributes = append(attributes, ike_message.BuildConfigurationAttribute(ike_message.INTERNAL_IP4_ADDRESS, ueIPAddr))
			}

			if addrRequestNumber >= 2 {
				// UE internal IP address
				for {
					ueIPAddr = GenRandomIPinRange(n3iwfSelf.Subnet)
					if ueIPAddr != nil {
						if _, ok := n3iwfSelf.AllocatedUEIPAddress[ueIPAddr.String()]; !ok {
							// Should be release if there is any error occur
							n3iwfSelf.AllocatedUEIPAddress[ueIPAddr.String()] = thisUE
							break
						}
					}
				}
				attributes = append(attributes, ike_message.BuildConfigurationAttribute(ike_message.INTERNAL_IP4_ADDRESS, ueIPAddr))

				// NAS IP ADDRESS
				nasIPAddressString := strings.Split(thisUE.AMF.SCTPAddr, ":")
				nasIPAddress := net.ParseIP(nasIPAddressString[0])
				attributes = append(attributes, ike_message.BuildConfigurationAttribute(ike_message.INTERNAL_IP4_ADDRESS, nasIPAddress))
			}

			// Prepare individual traffic selectors
			individualTrafficSelectorInitiator := ike_message.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
				0, 65535, ueIPAddr, ueIPAddr)
			individualTrafficSelectorResponder := ike_message.BuildIndividualTrafficSelector(ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
				0, 65535, net.IPv4zero, net.IPv4bcast)

			responseTrafficSelectorInitiator = ike_message.BuildTrafficSelectorInitiator([]*ike_message.IndividualTrafficSelector{individualTrafficSelectorInitiator})
			responseTrafficSelectorResponder = ike_message.BuildTrafficSelectorResponder([]*ike_message.IndividualTrafficSelector{individualTrafficSelectorResponder})

			responseConfiguration = ike_message.BuildConfigurationPayload(ike_message.CFG_REPLY, attributes)
		} else {
			ikeLog.Error("[IKE] UE did not send any configuration request for its IP address.")
			return
		}

		// Calculate local AUTH
		pseudorandomFunction, ok := NewPseudorandomFunction(thisUE.Kn3iwf, transformPseudorandomFunction.TransformID)
		if !ok {
			ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return
		}
		pseudorandomFunction.Write([]byte("Key Pad for IKEv2"))
		secret := pseudorandomFunction.Sum(nil)
		pseudorandomFunction, ok = NewPseudorandomFunction(secret, transformPseudorandomFunction.TransformID)
		if !ok {
			ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return
		}
		pseudorandomFunction.Write(ikeSecurityAssociation.LocalUnsignedAuthentication)

		// Build response
		var ikePayload []ike_message.IKEPayloadType

		// Configuration
		ikePayload = append(ikePayload, responseConfiguration)

		// Authentication
		responseAuthentication = ike_message.BuildAuthentication(ike_message.SharedKeyMesageIntegrityCode, pseudorandomFunction.Sum(nil))
		ikePayload = append(ikePayload, responseAuthentication)

		// Security Association
		responseSecurityAssociation = ikeSecurityAssociation.IKEAuthResponseSA
		ikePayload = append(ikePayload, responseSecurityAssociation)

		// Traffic Selector Initiator and Responder
		ikePayload = append(ikePayload, responseTrafficSelectorInitiator)
		ikePayload = append(ikePayload, responseTrafficSelectorResponder)

		// Encrypting
		ikePayloadData, err := ike_message.EncodePayload(ikePayload)
		if err != nil {
			ikeLog.Errorln(err)
			ikeLog.Error("[IKE] Encode payload failed.")
			return
		}
		encryptedIKEPayloadData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData, transformEncryptionAlgorithm.TransformID)
		if err != nil {
			ikeLog.Errorf("[IKE] Encrypting message failed: %+v", err)
			return
		}
		encryptedIKEPayloadData = append(encryptedIKEPayloadData, make([]byte, integrityKeyLength)...)
		responseEncryptedPayload = ike_message.BuildEncryptedPayload(ike_message.TypeCP, encryptedIKEPayloadData)

		// Build IKE message
		responseIKEMessage = ike_message.BuildIKEHeader(message.InitiatorSPI, message.ResponderSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck, message.MessageID)
		responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

		// Calculate checksum
		responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
		if err != nil {
			ikeLog.Errorln(err)
			ikeLog.Error("[IKE] Encode message failed.")
			return
		}
		checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar, responseIKEMessageData[:len(responseIKEMessageData)-integrityKeyLength], transformIntegrityAlgorithm.TransformID)
		if err != nil {
			ikeLog.Errorf("[IKE] Calculating checksum failed: %+v", err)
			return
		}
		checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-integrityKeyLength:]
		copy(checksumField, checksumOfMessage)

		// Send IKE message to UE
		ike_message.SendIKEMessageToUE(ueSendInfo, responseIKEMessage)
	}
}

func is_supported(transformType uint8, transformID uint16, attributePresent bool, attributeValue uint16) bool {
	switch transformType {
	case ike_message.TypeEncryptionAlgorithm:
		switch transformID {
		case ike_message.ENCR_DES_IV64:
			return false
		case ike_message.ENCR_DES:
			return false
		case ike_message.ENCR_3DES:
			return false
		case ike_message.ENCR_RC5:
			return false
		case ike_message.ENCR_IDEA:
			return false
		case ike_message.ENCR_CAST:
			return false
		case ike_message.ENCR_BLOWFISH:
			return false
		case ike_message.ENCR_3IDEA:
			return false
		case ike_message.ENCR_DES_IV32:
			return false
		case ike_message.ENCR_NULL:
			return false
		case ike_message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return true
				case 192:
					return true
				case 256:
					return true
				}
			} else {
				return false
			}
		case ike_message.ENCR_AES_CTR:
			return false
		default:
			return false
		}
	case ike_message.TypePseudorandomFunction:
		switch transformID {
		case ike_message.PRF_HMAC_MD5:
			return false
		case ike_message.PRF_HMAC_SHA1:
			return false
		case ike_message.PRF_HMAC_TIGER:
			return false
		default:
			return false
		}
	case ike_message.TypeIntegrityAlgorithm:
		switch transformID {
		case ike_message.AUTH_NONE:
			return false
		case ike_message.AUTH_HMAC_MD5_96:
			return false
		case ike_message.AUTH_HMAC_SHA1_96:
			return false
		case ike_message.AUTH_DES_MAC:
			return false
		case ike_message.AUTH_KPDK_MD5:
			return false
		case ike_message.AUTH_AES_XCBC_96:
			return false
		default:
			return false
		}
	case ike_message.TypeDiffieHellmanGroup:
		switch transformID {
		case ike_message.DH_NONE:
			return false
		case ike_message.DH_768_BIT_MODP:
			return false
		case ike_message.DH_1024_BIT_MODP:
			return false
		case ike_message.DH_1536_BIT_MODP:
			return false
		case ike_message.DH_2048_BIT_MODP:
			return false
		case ike_message.DH_3072_BIT_MODP:
			return false
		case ike_message.DH_4096_BIT_MODP:
			return false
		case ike_message.DH_6144_BIT_MODP:
			return false
		case ike_message.DH_8192_BIT_MODP:
			return false
		default:
			return false
		}
	case ike_message.TypeExtendedSequenceNumbers:
		switch transformID {
		case ike_message.ESN_NO:
			return true
		case ike_message.ESN_NEED:
			return false
		default:
			return false
		}
	default:
		return false
	}
	return false
}

func getKeyLength(transformType uint8, transformID uint16, attributePresent bool, attributeValue uint16) (int, bool) {
	switch transformType {
	case ike_message.TypeEncryptionAlgorithm:
		switch transformID {
		case ike_message.ENCR_DES_IV64:
			return 0, false
		case ike_message.ENCR_DES:
			return 0, false
		case ike_message.ENCR_3DES:
			return 0, false
		case ike_message.ENCR_RC5:
			return 0, false
		case ike_message.ENCR_IDEA:
			return 0, false
		case ike_message.ENCR_CAST:
			return 0, false
		case ike_message.ENCR_BLOWFISH:
			return 0, false
		case ike_message.ENCR_3IDEA:
			return 0, false
		case ike_message.ENCR_DES_IV32:
			return 0, false
		case ike_message.ENCR_NULL:
			return 0, false
		case ike_message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 192:
					return 24, true
				case 256:
					return 32, true
				}
			} else {
				return 0, false
			}
		case ike_message.ENCR_AES_CTR:
			return 0, false
		default:
			return 0, false
		}
	case ike_message.TypePseudorandomFunction:
		switch transformID {
		case ike_message.PRF_HMAC_MD5:
			return 0, false
		case ike_message.PRF_HMAC_SHA1:
			return 0, false
		case ike_message.PRF_HMAC_TIGER:
			return 0, false
		default:
			return 0, false
		}
	case ike_message.TypeIntegrityAlgorithm:
		switch transformID {
		case ike_message.AUTH_NONE:
			return 0, false
		case ike_message.AUTH_HMAC_MD5_96:
			return 0, false
		case ike_message.AUTH_HMAC_SHA1_96:
			return 0, false
		case ike_message.AUTH_DES_MAC:
			return 0, false
		case ike_message.AUTH_KPDK_MD5:
			return 0, false
		case ike_message.AUTH_AES_XCBC_96:
			return 0, false
		default:
			return 0, false
		}
	case ike_message.TypeDiffieHellmanGroup:
		switch transformID {
		case ike_message.DH_NONE:
			return 0, false
		case ike_message.DH_768_BIT_MODP:
			return 0, false
		case ike_message.DH_1024_BIT_MODP:
			return 0, false
		case ike_message.DH_1536_BIT_MODP:
			return 0, false
		case ike_message.DH_2048_BIT_MODP:
			return 0, false
		case ike_message.DH_3072_BIT_MODP:
			return 0, false
		case ike_message.DH_4096_BIT_MODP:
			return 0, false
		case ike_message.DH_6144_BIT_MODP:
			return 0, false
		case ike_message.DH_8192_BIT_MODP:
			return 0, false
		default:
			return 0, false
		}
	default:
		return 0, false
	}
	return 0, false
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}

func GenRandomIPinRange(subnet *net.IPNet) net.IP {
	ipAddr := make([]byte, 4)

	for i := 0; i < 4; i++ {
		randomNumber, err := GenerateRandomUint8()
		if err != nil {
			ikeLog.Error("[IKE] Generate random number for IP address failed: %+v", err)
			return nil
		}
		alter := byte(randomNumber) & (subnet.Mask[i] ^ 255)
		ipAddr[i] = subnet.IP[i] + alter
	}

	return net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}
