package ike

import (
	"testing"

	"github.com/stretchr/testify/require"

	ike_message "github.com/free5gc/ike/message"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

func TestHasExpectedMessageID(t *testing.T) {
	ikeSA := &n3iwf_context.IKESecurityAssociation{
		InitiatorMessageID: 3,
		ResponderMessageID: 7,
	}

	tests := []struct {
		name       string
		isResponse bool
		messageID  uint32
		expected   bool
	}{
		{name: "request exact match", messageID: 3, expected: true},
		{name: "request stale", messageID: 2, expected: false},
		{name: "request fast forward", messageID: 4, expected: false},
		{name: "response exact match", isResponse: true, messageID: 7, expected: true},
		{name: "response stale", isResponse: true, messageID: 6, expected: false},
		{name: "response fast forward", isResponse: true, messageID: 8, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := uint8(0)
			if tt.isResponse {
				flags = ike_message.ResponseBitCheck
			}
			message := &ike_message.IKEMessage{
				IKEHeader: &ike_message.IKEHeader{
					Flags:     flags,
					MessageID: tt.messageID,
				},
			}

			require.Equal(t, tt.expected, hasExpectedMessageID(message, ikeSA))
			require.Equal(t, uint32(3), ikeSA.InitiatorMessageID)
			require.Equal(t, uint32(7), ikeSA.ResponderMessageID)
		})
	}
}
