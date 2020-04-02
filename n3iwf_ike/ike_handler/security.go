package ike_handler

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"hash"
	"io"
	"math/big"

	"gofree5gc/src/n3iwf/n3iwf_context"
	"gofree5gc/src/n3iwf/n3iwf_ike/ike_message"
)

// General data
var randomNumberMaximum big.Int
var randomNumberMinimum big.Int

func init() {
	randomNumberMaximum.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
	randomNumberMinimum.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
}

func GenerateRandomNumber() *big.Int {
	var number *big.Int
	var err error
	for {
		number, err = rand.Int(rand.Reader, &randomNumberMaximum)
		if err != nil {
			ikeLog.Errorf("[IKE] Error occurs when generate random number: %+v", err)
			return nil
		} else {
			if number.Cmp(&randomNumberMinimum) == 1 {
				break
			}
		}
	}
	return number
}

func GenerateRandomUint8() (uint8, error) {
	number := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, number)
	if err != nil {
		ikeLog.Errorf("[IKE] Read random failed: %+v", err)
		return 0, errors.New("Read failed")
	}
	return uint8(number[0]), nil
}

// Diffie-Hellman Exchange
// The strength supplied by group 1 may not be sufficient for typical uses
const (
	Group2PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
	Group2Generator          = 2
)

func CalculateDiffieHellmanMaterials(secret *big.Int, peerPublicValue []byte, diffieHellmanGroupNumber uint16) (localPublicValue []byte, sharedKey []byte) {
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	var generator, factor *big.Int
	var ok bool

	switch diffieHellmanGroupNumber {
	case ike_message.DH_1024_BIT_MODP:
		generator = new(big.Int).SetUint64(Group2Generator)
		factor, ok = new(big.Int).SetString(Group2PrimeString, 16)
		if !ok {
			ikeLog.Errorf("[IKE] Error occurs when setting big number \"factor\" in %d group", diffieHellmanGroupNumber)
		}
	default:
		ikeLog.Errorf("[IKE] Unsupported Diffie-Hellman group: %d", diffieHellmanGroupNumber)
		return
	}

	localPublicValue = new(big.Int).Exp(generator, secret, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicValue))
	localPublicValue = append(prependZero, localPublicValue...)

	sharedKey = new(big.Int).Exp(peerPublicValueBig, secret, factor).Bytes()
	prependZero = make([]byte, len(factor.Bytes())-len(sharedKey))
	sharedKey = append(prependZero, sharedKey...)

	return
}

// Pseudorandom Funciton
func NewPseudorandomFunction(key []byte, algorithmType uint16) (hash.Hash, bool) {
	switch algorithmType {
	case ike_message.PRF_HMAC_MD5:
		return hmac.New(md5.New, key), true
	case ike_message.PRF_HMAC_SHA1:
		return hmac.New(sha1.New, key), true
	default:
		ikeLog.Errorf("[IKE] Unsupported pseudo random function: %d", algorithmType)
		return nil, false
	}
}

// Integrity Algorithm
func CalculateChecksum(key []byte, message []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case ike_message.AUTH_HMAC_MD5_96:
		if len(key) != 16 {
			return nil, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(md5.New, key)
		if _, err := integrityFunction.Write(message); err != nil {
			ikeLog.Errorf("[IKE] Hash function write error when calcualting checksum: %+v", err)
			return nil, errors.New("Hash function write error")
		}
		return integrityFunction.Sum(nil), nil
	default:
		ikeLog.Errorf("[IKE] Unsupported integrity function: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func VerifyIKEChecksum(key []byte, message []byte, checksum []byte, algorithmType uint16) (bool, error) {
	switch algorithmType {
	case ike_message.AUTH_HMAC_MD5_96:
		if len(key) != 16 {
			return false, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(md5.New, key)
		if _, err := integrityFunction.Write(message); err != nil {
			ikeLog.Errorf("[IKE] Hash function write error when verifying IKE checksum: %+v", err)
			return false, errors.New("Hash function write error")
		}
		checksumOfMessage := integrityFunction.Sum(nil)
		return hmac.Equal(checksumOfMessage, checksum), nil
	default:
		ikeLog.Errorf("[IKE] Unsupported integrity function: %d", algorithmType)
		return false, errors.New("Unsupported algorithm")
	}
}

// Encryption Algorithm
func EncryptMessage(key []byte, message []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case ike_message.ENCR_AES_CBC:
		// padding message
		message = PKCS7Padding(message, aes.BlockSize)
		block, err := aes.NewCipher(key)
		if err != nil {
			ikeLog.Errorf("[IKE] Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}

		cipherText := make([]byte, aes.BlockSize+len(message))
		initializationVector := cipherText[:aes.BlockSize]

		_, err = io.ReadFull(rand.Reader, initializationVector)
		if err != nil {
			ikeLog.Errorf("[IKE] Read random failed: %+v", err)
			return nil, errors.New("Read random initialization vector failed")
		}

		cbcBlockMode := cipher.NewCBCEncrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], message)

		return cipherText, nil
	default:
		ikeLog.Errorf("[IKE] Unsupported encryption algorithm: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func DecryptMessage(key []byte, cipherText []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case ike_message.ENCR_AES_CBC:
		if len(cipherText) < aes.BlockSize {
			ikeLog.Error("[IKE] Length of cipher text is too short to decrypt")
			return nil, errors.New("Cipher text is too short")
		}

		initializationVector := cipherText[:aes.BlockSize]
		encryptedMessage := cipherText[aes.BlockSize:]

		if len(encryptedMessage)%aes.BlockSize != 0 {
			ikeLog.Error("[IKE] Cipher text is not a multiple of block size")
			return nil, errors.New("Cipher text length error")
		}

		plainText := make([]byte, len(encryptedMessage))

		block, err := aes.NewCipher(key)
		if err != nil {
			ikeLog.Errorf("[IKE] Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}
		cbcBlockMode := cipher.NewCBCDecrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

		padding := int(plainText[len(plainText)-1])
		plainText = plainText[:len(plainText)-padding]

		return plainText, nil
	default:
		ikeLog.Errorf("[IKE] Unsupported encryption algorithm: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func PKCS7Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, paddingText...)
}

// Certificate
func CompareRootCertificate(certificateEncoding uint8, requestedCertificateAuthorityHash []byte) bool {
	if certificateEncoding != ike_message.X509CertificateSignature {
		ikeLog.Debugf("Not support certificate type: %d. Reject.", certificateEncoding)
		return false
	}

	n3iwfSelf := n3iwf_context.N3IWFSelf()

	if len(n3iwfSelf.CertificateAuthority) == 0 {
		ikeLog.Error("[IKE] Certificate authority in context is empty")
		return false
	}

	return bytes.Equal(n3iwfSelf.CertificateAuthority, requestedCertificateAuthorityHash)
}

// Key Gen for IKE SA
func GenerateKeyForIKESA(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.PseudorandomFunction == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikeSecurityAssociation.DiffieHellmanGroup == nil {
		return errors.New("No Diffie-hellman group algorithm specified")
	}

	if len(ikeSecurityAssociation.ConcatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(ikeSecurityAssociation.DiffieHellmanSharedKey) == 0 {
		return errors.New("No Diffie-Hellman shared key")
	}

	// Transforms
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int
	var ok bool

	if length_SK_d, ok = getKeyLength(transformPseudorandomFunction.TransformType, transformPseudorandomFunction.TransformID, transformPseudorandomFunction.AttributePresent, transformPseudorandomFunction.AttributeValue); !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return errors.New("Get key length failed")
	}
	if length_SK_ai, ok = getKeyLength(transformIntegrityAlgorithm.TransformType, transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent, transformIntegrityAlgorithm.AttributeValue); !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_ar = length_SK_ai
	if length_SK_ei, ok = getKeyLength(transformEncryptionAlgorithm.TransformType, transformEncryptionAlgorithm.TransformID, transformEncryptionAlgorithm.AttributePresent, transformEncryptionAlgorithm.AttributeValue); !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = NewPseudorandomFunction(ikeSecurityAssociation.ConcatenatedNonce, transformPseudorandomFunction.TransformID); !ok {
		ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return errors.New("New pseudorandom function failed")
	}
	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.DiffieHellmanSharedKey); err != nil {
		ikeLog.Errorf("[IKE] Pseudorandom function write error: %+v", err)
		return errors.New("Pseudorandom function write failed")
	}

	SKEYSEED := pseudorandomFunction.Sum(nil)
	seed := concatenateNonceAndSPI(ikeSecurityAssociation.ConcatenatedNonce, ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			ikeLog.Errorf("[IKE] Pseudorandom function write error: %+v", err)
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	// Assign keys into context
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

	return nil
}

// Key Gen for child SA
func GenerateKeyForChildSA(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation, childSecurityAssociation *n3iwf_context.ChildSecurityAssociation) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}
	if childSecurityAssociation == nil {
		return errors.New("Child SA is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.PseudorandomFunction == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikeSecurityAssociation.IKEAuthResponseSA == nil {
		return errors.New("No IKE_AUTH response SA specified")
	}
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals) == 0 {
		return errors.New("No proposal in IKE_AUTH response SA")
	}
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].EncryptionAlgorithm) == 0 {
		return errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_d) == 0 {
		return errors.New("No key deriving key")
	}

	// Transforms
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction
	transformEncryptionAlgorithmForIPSec := ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].EncryptionAlgorithm[0]
	var transformIntegrityAlgorithmForIPSec *ike_message.Transform
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm) != 0 {
		transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm[0]
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int
	var ok bool

	if lengthEncryptionKeyIPSec, ok = getKeyLength(transformEncryptionAlgorithmForIPSec.TransformType, transformEncryptionAlgorithmForIPSec.TransformID, transformEncryptionAlgorithmForIPSec.AttributePresent, transformEncryptionAlgorithmForIPSec.AttributeValue); !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return errors.New("Get key length failed")
	}
	if transformIntegrityAlgorithmForIPSec != nil {
		if lengthIntegrityKeyIPSec, ok = getKeyLength(transformIntegrityAlgorithmForIPSec.TransformType, transformIntegrityAlgorithmForIPSec.TransformID, transformIntegrityAlgorithmForIPSec.AttributePresent, transformIntegrityAlgorithmForIPSec.AttributeValue); !ok {
			ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
			return errors.New("Get key length failed")
		}
	}
	totalKeyLength = lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec
	totalKeyLength = totalKeyLength * 2

	// Generate key for child security association as specified in RFC 7296 section 2.17
	seed := ikeSecurityAssociation.ConcatenatedNonce
	var pseudorandomFunction hash.Hash

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = NewPseudorandomFunction(ikeSecurityAssociation.SK_d, transformPseudorandomFunction.TransformID); !ok {
			ikeLog.Error("[IKE] Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			ikeLog.Errorf("[IKE] Pseudorandom function write error: %+v", err)
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	childSecurityAssociation.IncomingEncryptionKey = append(childSecurityAssociation.IncomingEncryptionKey, keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.IncomingIntegrityKey = append(childSecurityAssociation.IncomingIntegrityKey, keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childSecurityAssociation.OutgoingEncryptionKey = append(childSecurityAssociation.OutgoingEncryptionKey, keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.OutgoingIntegrityKey = append(childSecurityAssociation.OutgoingIntegrityKey, keyStream[:lengthIntegrityKeyIPSec]...)

	return nil

}

// Decrypt
func DecryptProcedure(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation, message *ike_message.IKEMessage, encryptedPayload *ike_message.Encrypted) ([]ike_message.IKEPayloadType, error) {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return nil, errors.New("IKE SA is nil")
	}
	if message == nil {
		return nil, errors.New("IKE message is nil")
	}
	if encryptedPayload == nil {
		return nil, errors.New("IKE encrypted payload is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return nil, errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return nil, errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_ai) == 0 {
		return nil, errors.New("No initiator's integrity key")
	}
	if len(ikeSecurityAssociation.SK_ei) == 0 {
		return nil, errors.New("No initiator's encryption key")
	}

	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	integrityKeyLength, ok := getKeyLength(transformIntegrityAlgorithm.TransformType, transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent, transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return nil, errors.New("Get key length failed")
	}

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-integrityKeyLength:]

	ikeMessageData, err := ike_message.Encode(message)
	if err != nil {
		ikeLog.Errorln(err)
		ikeLog.Error("Error occur when encoding for checksum")
		return nil, errors.New("Encoding IKE message failed")
	}

	ok, err = VerifyIKEChecksum(ikeSecurityAssociation.SK_ai, ikeMessageData[:len(ikeMessageData)-integrityKeyLength], checksum, transformIntegrityAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("[IKE] Error occur when verifying checksum: %+v", err)
		return nil, errors.New("Error verify checksum")
	}
	if !ok {
		ikeLog.Warn("[IKE] Message checksum failed. Drop the message.")
		return nil, errors.New("Checksum failed, drop.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-integrityKeyLength]
	plainText, err := DecryptMessage(ikeSecurityAssociation.SK_ei, encryptedData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("[IKE] Error occur when decrypting message: %+v", err)
		return nil, errors.New("Error decrypting message")
	}

	decryptedIKEPayload, err := ike_message.DecodePayload(encryptedPayload.NextPayload, plainText)
	if err != nil {
		ikeLog.Errorln(err)
		return nil, errors.New("Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil

}

// Encrypt
func EncryptProcedure(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation, ikePayload []ike_message.IKEPayloadType, responseIKEMessage *ike_message.IKEMessage) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}
	if len(ikePayload) == 0 {
		return errors.New("No IKE payload to be encrypted")
	}
	if responseIKEMessage == nil {
		return errors.New("Response IKE message is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_ar) == 0 {
		return errors.New("No responder's integrity key")
	}
	if len(ikeSecurityAssociation.SK_er) == 0 {
		return errors.New("No responder's encryption key")
	}

	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	integrityKeyLength, ok := getKeyLength(transformIntegrityAlgorithm.TransformType, transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent, transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		ikeLog.Error("[IKE] Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return errors.New("Get key length failed")
	}

	// Encrypting
	notificationPayloadData, err := ike_message.EncodePayload(ikePayload)
	if err != nil {
		ikeLog.Error(err)
		return errors.New("Encoding IKE payload failed.")
	}

	encryptedData, err := EncryptMessage(ikeSecurityAssociation.SK_er, notificationPayloadData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("[IKE] Encrypting data error: %+v", err)
		return errors.New("Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, integrityKeyLength)...)
	responseEncryptedPayload := ike_message.BuildEncryptedPayload(ikePayload[0].Type(), encryptedData)

	responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

	// Calculate checksum
	responseIKEMessageData, err := ike_message.Encode(responseIKEMessage)
	if err != nil {
		ikeLog.Error(err)
		return errors.New("Encoding IKE message error")
	}
	checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar, responseIKEMessageData[:len(responseIKEMessageData)-integrityKeyLength], transformIntegrityAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("[IKE] Calculating checksum failed: %+v", err)
		return errors.New("Error calculating checksum")
	}
	checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-integrityKeyLength:]
	copy(checksumField, checksumOfMessage)

	return nil

}
