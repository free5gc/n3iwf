package ike

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/n3iwf/pkg/factory"
	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
)

func TestRemoveIkeUe(t *testing.T) {
	n3iwf, err := NewN3iwfTestApp(&factory.Config{})
	require.NoError(t, err)

	n3iwf.ikeServer, err = NewServer(n3iwf)
	require.NoError(t, err)

	n3iwfCtx := n3iwf.n3iwfCtx
	ikeSA := n3iwfCtx.NewIKESecurityAssociation()
	ikeUe := n3iwfCtx.NewN3iwfIkeUe(ikeSA.LocalSPI)
	ikeUe.N3IWFIKESecurityAssociation = ikeSA
	ikeSA.IsUseDPD = false

	ikeUe.CreateHalfChildSA(1, 123, 1)

	ikeAuth := &ike_message.SecurityAssociation{}

	ikeAuth.Proposals.BuildProposal(1, 1, []byte{0, 1, 2, 3})

	childSA, err := ikeUe.CompleteChildSA(1, 456, ikeAuth)
	require.NoError(t, err)

	err = n3iwf.ikeServer.removeIkeUe(ikeSA.LocalSPI)
	require.NoError(t, err)

	_, ok := n3iwfCtx.IkeUePoolLoad(ikeSA.LocalSPI)
	require.False(t, ok)

	_, ok = n3iwfCtx.IKESALoad(ikeSA.LocalSPI)
	require.False(t, ok)

	_, ok = ikeUe.N3IWFChildSecurityAssociation[childSA.InboundSPI]
	require.False(t, ok)
}
