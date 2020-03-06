package ike_handler

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
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

func CompareRootCertificate(requestedCertificateAuthorityHash []byte, certificateEncoding uint8) bool {
	n3iwfSelf := n3iwf_context.N3IWFSelf()

	if len(n3iwfSelf.CertificateAuthority) == 0 {
		ikeLog.Error("[IKE] Certificate authority in context is empty")
		return false
	}

	certificateBlock, _ := pem.Decode(n3iwfSelf.CertificateAuthority)
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		ikeLog.Errorf("[IKE] Parse certificate error: %+v", err)
		return false
	}

	var rsaPublicKey *rsa.PublicKey

	switch certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaPublicKey = certificate.PublicKey.(*rsa.PublicKey)
	default:
		ikeLog.Error("Unsupported public key type")
		return false
	}

	rsaPublicKeyData := x509.MarshalPKCS1PublicKey(rsaPublicKey)

	hashFunction := sha1.New()
	if _, err := hashFunction.Write(rsaPublicKeyData); err != nil {
		ikeLog.Errorf("[IKE] Hash function write error when compare root certificate: %+v", err)
		return false
	}

	certificateAuthorityPublicKeySHA1 := hashFunction.Sum(nil)

	return bytes.Equal(certificateAuthorityPublicKeySHA1, requestedCertificateAuthorityHash)
}
