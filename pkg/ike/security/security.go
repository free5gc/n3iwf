package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"strings"

	"github.com/pkg/errors"

	"github.com/free5gc/n3iwf/internal/logger"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/ike/message"
)

// General data
var (
	randomNumberMaximum big.Int
	randomNumberMinimum big.Int
)

func init() {
	randomNumberMaximum.SetString(strings.Repeat("F", 512), 16)
	randomNumberMinimum.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
}

func GenerateRandomNumber() *big.Int {
	var number *big.Int
	var err error

	ikeLog := logger.IKELog
	for {
		number, err = rand.Int(rand.Reader, &randomNumberMaximum)
		if err != nil {
			ikeLog.Errorf("Error occurs when generate random number: %+v", err)
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
	ikeLog := logger.IKELog
	number := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, number)
	if err != nil {
		ikeLog.Errorf("Read random failed: %+v", err)
		return 0, errors.New("Read failed")
	}
	return number[0], nil
}

// Diffie-Hellman Exchange
// The strength supplied by group 1 may not be sufficient for typical uses
const (
	Group2PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE65381FFFFFFFFFFFFFFFF"
	Group2Generator           = 2
	Group14PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF05" +
		"98DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB" +
		"9ED529077096966D670C354E4ABC9804" +
		"F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28F" +
		"B5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	Group14Generator = 2
)

func CalculateDiffieHellmanMaterials(secret *big.Int, peerPublicValue []byte,
	diffieHellmanGroupNumber uint16,
) (localPublicValue []byte, sharedKey []byte) {
	ikeLog := logger.IKELog
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	var generator, factor *big.Int
	var ok bool

	switch diffieHellmanGroupNumber {
	case message.DH_1024_BIT_MODP:
		generator = new(big.Int).SetUint64(Group2Generator)
		factor, ok = new(big.Int).SetString(Group2PrimeString, 16)
		if !ok {
			ikeLog.Errorf(
				"Error occurs when setting big number \"factor\" in %d group",
				diffieHellmanGroupNumber)
		}
	case message.DH_2048_BIT_MODP:
		generator = new(big.Int).SetUint64(Group14Generator)
		factor, ok = new(big.Int).SetString(Group14PrimeString, 16)
		if !ok {
			ikeLog.Errorf(
				"Error occurs when setting big number \"factor\" in %d group",
				diffieHellmanGroupNumber)
		}
	default:
		ikeLog.Errorf("Unsupported Diffie-Hellman group: %d", diffieHellmanGroupNumber)
		return localPublicValue, sharedKey
	}

	localPublicValue = new(big.Int).Exp(generator, secret, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicValue))
	localPublicValue = append(prependZero, localPublicValue...)

	sharedKey = new(big.Int).Exp(peerPublicValueBig, secret, factor).Bytes()
	prependZero = make([]byte, len(factor.Bytes())-len(sharedKey))
	sharedKey = append(prependZero, sharedKey...)

	return localPublicValue, sharedKey
}

// Pseudorandom Function
func NewPseudorandomFunction(key []byte, algorithmType uint16) (hash.Hash, bool) {
	ikeLog := logger.IKELog
	switch algorithmType {
	case message.PRF_HMAC_MD5:
		return hmac.New(md5.New, key), true
	case message.PRF_HMAC_SHA1:
		return hmac.New(sha1.New, key), true // #nosec G401
	case message.PRF_HMAC_SHA2_256:
		return hmac.New(sha256.New, key), true
	default:
		ikeLog.Errorf("Unsupported pseudo random function: %d", algorithmType)
		return nil, false
	}
}

// Integrity Algorithm
func calculateIntegrity(key []byte, originData []byte, transform *message.Transform) ([]byte, error) {
	expectKeyLen, ok := getKeyLength(
		transform.TransformType, transform.TransformID,
		transform.AttributePresent, transform.AttributeValue)
	if !ok {
		return nil, errors.Errorf("calculateIntegrity[%d]: unsupported algo", transform.TransformID)
	}
	keyLen := len(key)
	if keyLen != expectKeyLen {
		return nil, errors.Errorf("calculateIntegrity[%d]: Unmatched input key length[%d:%d]",
			transform.TransformID, keyLen, expectKeyLen)
	}
	outputLen, ok := getOutputLength(
		transform.TransformType, transform.TransformID,
		transform.AttributePresent, transform.AttributeValue)
	if !ok {
		return nil, errors.Errorf("calculateIntegrity[%d]: unsupported algo", transform.TransformID)
	}

	var integrityFunction hash.Hash
	switch transform.TransformID {
	case message.AUTH_HMAC_MD5_96:
		integrityFunction = hmac.New(md5.New, key)
	case message.AUTH_HMAC_SHA1_96:
		integrityFunction = hmac.New(sha1.New, key) // #nosec G401
	case message.AUTH_HMAC_SHA2_256_128:
		integrityFunction = hmac.New(sha256.New, key)
	default:
		return nil, errors.Errorf("calculateIntegrity[%d]: unsupported algo", transform.TransformID)
	}

	if _, err := integrityFunction.Write(originData); err != nil {
		return nil, errors.Wrapf(err, "calculateIntegrity[%d]", transform.TransformID)
	}
	return integrityFunction.Sum(nil)[:outputLen], nil
}

func verifyIntegrity(key []byte, originData []byte, checksum []byte, transform *message.Transform) (bool, error) {
	ikeLog := logger.IKELog
	expectChecksum, err := calculateIntegrity(key, originData, transform)
	if err != nil {
		return false, errors.Wrapf(err, "verifyIntegrity")
	}

	ikeLog.Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s",
		hex.Dump(expectChecksum), hex.Dump(checksum))
	return hmac.Equal(expectChecksum, checksum), nil
}

// Encryption Algorithm
func EncryptMessage(key []byte, originData []byte, algorithmType uint16) ([]byte, error) {
	ikeLog := logger.IKELog
	switch algorithmType {
	case message.ENCR_AES_CBC:
		// padding message
		originData = PKCS7Padding(originData, aes.BlockSize)
		originData[len(originData)-1]--

		block, err := aes.NewCipher(key)
		if err != nil {
			ikeLog.Errorf("Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}

		cipherText := make([]byte, aes.BlockSize+len(originData))
		initializationVector := cipherText[:aes.BlockSize]

		_, err = io.ReadFull(rand.Reader, initializationVector)
		if err != nil {
			ikeLog.Errorf("Read random failed: %+v", err)
			return nil, errors.New("Read random initialization vector failed")
		}

		cbcBlockMode := cipher.NewCBCEncrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], originData)

		return cipherText, nil
	default:
		ikeLog.Errorf("Unsupported encryption algorithm: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func DecryptMessage(key []byte, cipherText []byte, algorithmType uint16) ([]byte, error) {
	ikeLog := logger.IKELog
	switch algorithmType {
	case message.ENCR_AES_CBC:
		if len(cipherText) < aes.BlockSize {
			ikeLog.Error("Length of cipher text is too short to decrypt")
			return nil, errors.New("Cipher text is too short")
		}

		initializationVector := cipherText[:aes.BlockSize]
		encryptedMessage := cipherText[aes.BlockSize:]

		if len(encryptedMessage)%aes.BlockSize != 0 {
			ikeLog.Error("Cipher text is not a multiple of block size")
			return nil, errors.New("Cipher text length error")
		}

		plainText := make([]byte, len(encryptedMessage))

		block, err := aes.NewCipher(key)
		if err != nil {
			ikeLog.Errorf("Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}
		cbcBlockMode := cipher.NewCBCDecrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

		ikeLog.Tracef("Decrypted content:\n%s", hex.Dump(plainText))

		padding := int(plainText[len(plainText)-1]) + 1
		plainText = plainText[:len(plainText)-padding]

		ikeLog.Tracef("Decrypted content with out padding:\n%s", hex.Dump(plainText))

		return plainText, nil
	default:
		ikeLog.Errorf("Unsupported encryption algorithm: %d", algorithmType)
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
func CompareRootCertificate(
	ca []byte,
	certificateEncoding uint8,
	requestedCertificateAuthorityHash []byte,
) bool {
	ikeLog := logger.IKELog
	if certificateEncoding != message.X509CertificateSignature {
		ikeLog.Debugf("Not support certificate type: %d. Reject.", certificateEncoding)
		return false
	}

	if len(ca) == 0 {
		ikeLog.Error("Certificate authority in context is empty")
		return false
	}

	return bytes.Equal(ca, requestedCertificateAuthorityHash)
}

// Key Gen for IKE SA
func GenerateKeyForIKESA(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation) error {
	ikeLog := logger.IKELog
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

	if length_SK_d, ok = getKeyLength(transformPseudorandomFunction.TransformType,
		transformPseudorandomFunction.TransformID, transformPseudorandomFunction.AttributePresent,
		transformPseudorandomFunction.AttributeValue); !ok {
		ikeLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	if length_SK_ai, ok = getKeyLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue); !ok {
		ikeLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_ar = length_SK_ai
	if length_SK_ei, ok = getKeyLength(transformEncryptionAlgorithm.TransformType,
		transformEncryptionAlgorithm.TransformID, transformEncryptionAlgorithm.AttributePresent,
		transformEncryptionAlgorithm.AttributeValue); !ok {
		ikeLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = NewPseudorandomFunction(ikeSecurityAssociation.ConcatenatedNonce,
		transformPseudorandomFunction.TransformID); !ok {
		ikeLog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return errors.New("New pseudorandom function failed")
	}

	ikeLog.Tracef("DH shared key:\n%s", hex.Dump(ikeSecurityAssociation.DiffieHellmanSharedKey))
	ikeLog.Tracef("Concatenated nonce:\n%s", hex.Dump(ikeSecurityAssociation.ConcatenatedNonce))

	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.DiffieHellmanSharedKey); err != nil {
		ikeLog.Errorf("Pseudorandom function write error: %+v", err)
		return errors.New("Pseudorandom function write failed")
	}

	SKEYSEED := pseudorandomFunction.Sum(nil)

	ikeLog.Tracef("SKEYSEED:\n%s", hex.Dump(SKEYSEED))

	seed := concatenateNonceAndSPI(ikeSecurityAssociation.ConcatenatedNonce,
		ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			ikeLog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			ikeLog.Errorf("Pseudorandom function write error: %+v", err)
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
	// keyStream = keyStream[length_SK_pr:]

	ikeLog.Debugln("====== IKE Security Association Info =====")
	ikeLog.Debugf("Initiator's SPI: %016x", ikeSecurityAssociation.RemoteSPI)
	ikeLog.Debugf("Responder's  SPI: %016x", ikeSecurityAssociation.LocalSPI)
	ikeLog.Debugf("Encryption Algorithm: %d", ikeSecurityAssociation.EncryptionAlgorithm.TransformID)
	ikeLog.Debugf("SK_ei: %x", ikeSecurityAssociation.SK_ei)
	ikeLog.Debugf("SK_er: %x", ikeSecurityAssociation.SK_er)
	ikeLog.Debugf("Integrity Algorithm: %d", ikeSecurityAssociation.IntegrityAlgorithm.TransformID)
	ikeLog.Debugf("SK_ai: %x", ikeSecurityAssociation.SK_ai)
	ikeLog.Debugf("SK_ar: %x", ikeSecurityAssociation.SK_ar)
	ikeLog.Debugf("SK_pi: %x", ikeSecurityAssociation.SK_pi)
	ikeLog.Debugf("SK_pr: %x", ikeSecurityAssociation.SK_pr)

	return nil
}

// Key Gen for child SA
func GenerateKeyForChildSA(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation,
	childSecurityAssociation *n3iwf_context.ChildSecurityAssociation,
) error {
	ikeLog := logger.IKELog
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
	var transformIntegrityAlgorithmForIPSec *message.Transform
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm) != 0 {
		transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm[0]
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int
	var ok bool

	if lengthEncryptionKeyIPSec, ok = getKeyLength(transformEncryptionAlgorithmForIPSec.TransformType,
		transformEncryptionAlgorithmForIPSec.TransformID,
		transformEncryptionAlgorithmForIPSec.AttributePresent,
		transformEncryptionAlgorithmForIPSec.AttributeValue); !ok {
		ikeLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	if transformIntegrityAlgorithmForIPSec != nil {
		if lengthIntegrityKeyIPSec, ok = getKeyLength(transformIntegrityAlgorithmForIPSec.TransformType,
			transformIntegrityAlgorithmForIPSec.TransformID,
			transformIntegrityAlgorithmForIPSec.AttributePresent,
			transformIntegrityAlgorithmForIPSec.AttributeValue); !ok {
			ikeLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
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
		if pseudorandomFunction, ok = NewPseudorandomFunction(ikeSecurityAssociation.SK_d,
			transformPseudorandomFunction.TransformID); !ok {
			ikeLog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			ikeLog.Errorf("Pseudorandom function write error: %+v", err)
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	childSecurityAssociation.InitiatorToResponderEncryptionKey = append(
		childSecurityAssociation.InitiatorToResponderEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.InitiatorToResponderIntegrityKey = append(
		childSecurityAssociation.InitiatorToResponderIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorEncryptionKey = append(
		childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorIntegrityKey = append(
		childSecurityAssociation.ResponderToInitiatorIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)

	return nil
}

// Decrypt
func DecryptProcedure(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation, ikeMessage *message.IKEMessage,
	encryptedPayload *message.Encrypted,
) (message.IKEPayloadContainer, error) {
	ikeLog := logger.IKELog
	// Check parameters
	if ikeSecurityAssociation == nil {
		return nil, errors.New("IKE SA is nil")
	}
	if ikeMessage == nil {
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
	checksumLength, ok := getOutputLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		ikeLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return nil, errors.New("Get key length failed")
	}

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		ikeLog.Errorln(err)
		ikeLog.Error("Error occur when encoding for checksum")
		return nil, errors.New("Encoding IKE message failed")
	}

	ok, err = verifyIntegrity(ikeSecurityAssociation.SK_ai,
		ikeMessageData[:len(ikeMessageData)-checksumLength], checksum,
		transformIntegrityAlgorithm)
	if err != nil {
		ikeLog.Errorf("Error occur when verifying checksum: %+v", err)
		return nil, errors.New("Error verify checksum")
	}
	if !ok {
		ikeLog.Warn("Message checksum failed. Drop the message.")
		return nil, errors.New("Checksum failed, drop.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := DecryptMessage(ikeSecurityAssociation.SK_ei, encryptedData,
		transformEncryptionAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("Error occur when decrypting message: %+v", err)
		return nil, errors.New("Error decrypting message")
	}

	var decryptedIKEPayload message.IKEPayloadContainer
	err = decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		ikeLog.Errorln(err)
		return nil, errors.New("Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil
}

// Encrypt
func EncryptProcedure(ikeSecurityAssociation *n3iwf_context.IKESecurityAssociation,
	ikePayload message.IKEPayloadContainer, responseIKEMessage *message.IKEMessage,
) error {
	ikeLog := logger.IKELog
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
	checksumLength, ok := getOutputLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		ikeLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}

	// Encrypting
	ikePayloadData, err := ikePayload.Encode()
	if err != nil {
		ikeLog.Error(err)
		return errors.New("Encoding IKE payload failed.")
	}

	encryptedData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData,
		transformEncryptionAlgorithm.TransformID)
	if err != nil {
		ikeLog.Errorf("Encrypting data error: %+v", err)
		return errors.New("Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	sk := responseIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	responseIKEMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		ikeLog.Error(err)
		return errors.New("Encoding IKE message error")
	}
	checksumOfMessage, err := calculateIntegrity(ikeSecurityAssociation.SK_ar,
		responseIKEMessageData[:len(responseIKEMessageData)-checksumLength],
		transformIntegrityAlgorithm)
	if err != nil {
		ikeLog.Errorf("Calculating checksum failed: %+v", err)
		return errors.New("Error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil
}

// Get information of algorithm
func getKeyLength(transformType uint8, transformID uint16, attributePresent bool,
	attributeValue uint16,
) (int, bool) {
	switch transformType {
	case message.TypeEncryptionAlgorithm:
		switch transformID {
		case message.ENCR_DES_IV64:
			return 0, false
		case message.ENCR_DES:
			return 8, true
		case message.ENCR_3DES:
			return 24, true
		case message.ENCR_RC5:
			return 0, false
		case message.ENCR_IDEA:
			return 0, false
		case message.ENCR_CAST:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 256:
					return 0, false
				default:
					return 0, false
				}
			}
			return 0, false
		case message.ENCR_BLOWFISH: // Blowfish support variable key length
			if attributePresent {
				if attributeValue < 40 {
					return 0, false
				} else if attributeValue > 448 {
					return 0, false
				} else {
					return int(attributeValue / 8), true
				}
			} else {
				return 0, false
			}
		case message.ENCR_3IDEA:
			return 0, false
		case message.ENCR_DES_IV32:
			return 0, false
		case message.ENCR_NULL:
			return 0, true
		case message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 192:
					return 24, true
				case 256:
					return 32, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		case message.ENCR_AES_CTR:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 20, true
				case 192:
					return 28, true
				case 256:
					return 36, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		default:
			return 0, false
		}
	case message.TypePseudorandomFunction:
		switch transformID {
		case message.PRF_HMAC_MD5:
			return 16, true
		case message.PRF_HMAC_SHA1:
			return 20, true
		case message.PRF_HMAC_SHA2_256:
			return 32, true
		case message.PRF_HMAC_TIGER:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return 0, false
		case message.AUTH_HMAC_MD5_96:
			return 16, true
		case message.AUTH_HMAC_SHA1_96:
			return 20, true
		case message.AUTH_DES_MAC:
			return 0, false
		case message.AUTH_KPDK_MD5:
			return 0, false
		case message.AUTH_AES_XCBC_96:
			return 0, false
		case message.AUTH_HMAC_SHA2_256_128:
			return 32, true
		default:
			return 0, false
		}
	case message.TypeDiffieHellmanGroup:
		switch transformID {
		case message.DH_NONE:
			return 0, false
		case message.DH_768_BIT_MODP:
			return 0, false
		case message.DH_1024_BIT_MODP:
			return 0, false
		case message.DH_1536_BIT_MODP:
			return 0, false
		case message.DH_2048_BIT_MODP:
			return 0, false
		case message.DH_3072_BIT_MODP:
			return 0, false
		case message.DH_4096_BIT_MODP:
			return 0, false
		case message.DH_6144_BIT_MODP:
			return 0, false
		case message.DH_8192_BIT_MODP:
			return 0, false
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func getOutputLength(
	transformType uint8,
	transformID uint16,
	attributePresent bool,
	attributeValue uint16,
) (int, bool) {
	_ = attributePresent
	_ = attributeValue

	switch transformType {
	case message.TypePseudorandomFunction:
		switch transformID {
		case message.PRF_HMAC_MD5:
			return 16, true
		case message.PRF_HMAC_SHA1:
			return 20, true
		case message.PRF_HMAC_TIGER:
			return 0, false
		case message.PRF_HMAC_SHA2_256:
			return 32, true
		default:
			return 0, false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return 0, false
		case message.AUTH_HMAC_MD5_96:
			return 12, true
		case message.AUTH_HMAC_SHA1_96:
			return 12, true
		case message.AUTH_DES_MAC:
			return 0, false
		case message.AUTH_KPDK_MD5:
			return 0, false
		case message.AUTH_AES_XCBC_96:
			return 0, false
		case message.AUTH_HMAC_SHA2_256_128:
			return 16, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}
