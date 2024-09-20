package security

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/n3iwf/pkg/ike/message"
)

func TestVerifyIntegrity(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		originData    []byte
		checksum      string
		transform     *message.Transform
		expectedValid bool
	}{
		{
			name:       "HMAC MD5 96 - valid",
			key:        "0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "c30f366e411540f68221d04a",
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_MD5_96,
			},
			expectedValid: true,
		},
		{
			name:       "HMAC MD5 96 - invalid checksum",
			key:        "0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_MD5_96,
			},
			expectedValid: false,
		},
		{
			name:       "HMAC MD5 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_MD5_96,
			},
			expectedValid: false,
		},
		{
			name:       "HMAC SHA1 96 - valid",
			key:        "0123456789abcdef0123456789abcdef01234567",
			originData: []byte("hello world"),
			checksum:   "5089f6a86e4dafb89e3fcd23",
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_SHA1_96,
			},
			expectedValid: true,
		},
		{
			name:       "HMAC SHA1 96 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef01234567",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_SHA1_96,
			},
			expectedValid: false,
		},
		{
			name:       "HMAC SHA1 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_SHA1_96,
			},
			expectedValid: false,
		},
		{
			name:       "HMAC SHA256 128 - valid",
			key:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "a64166565bc1f48eb3edd4109fcaeb72",
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_SHA2_256_128,
			},
			expectedValid: true,
		},
		{
			name:       "HMAC SHA256 128 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_SHA1_96,
			},
			expectedValid: false,
		},
		{
			name:       "HMAC SHA256 128 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			transform: &message.Transform{
				TransformType: message.TypeIntegrityAlgorithm,
				TransformID:   message.AUTH_HMAC_SHA1_96,
			},
			expectedValid: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key, checksum []byte
			var err error
			checksum, err = hex.DecodeString(tt.checksum)
			require.NoError(t, err, "failed to decode checksum hex string")

			key, err = hex.DecodeString(tt.key)
			require.NoError(t, err, "failed to decode key hex string")

			valid, err := verifyIntegrity(key, tt.originData, checksum, tt.transform)
			if tt.expectedValid {
				require.NoError(t, err, "verifyIntegrity returned an error")
			}
			require.Equal(t, tt.expectedValid, valid)
		})
	}
}
