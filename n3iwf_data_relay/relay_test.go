package n3iwf_data_relay_test

import (
	"gofree5gc/src/n3iwf/n3iwf_context"
	"gofree5gc/src/n3iwf/n3iwf_data_relay"
	"testing"
)

func TestUserPlaneRelay(t *testing.T) {
	// Prepare N3IWF context
	n3iwfSelf := n3iwf_context.N3IWFSelf()

	// Prepare UE context
	ue := n3iwfSelf.NewN3iwfUe()

	n3iwfSelf.IPSecGatewayAddress = "10.0.0.1"

	if err := n3iwf_data_relay.ListenN1(); err != nil {
		t.Fatal(err)
	}

	n3iwfSelf.GTPBindAddress = "192.168.x.x"

	userPlaneConn, remoteAddr, err := n3iwf_data_relay.SetupGTP("192.168.x.x")
	if err != nil {
		t.Fatal(err)
	}

	ueTEID := n3iwfSelf.NewTEID(ue)

	gtpConnection := &n3iwf_context.GTPConnectionInfo{
		RemoteAddr:          remoteAddr,
		IncomingTEID:        ueTEID,
		OutgoingTEID:        1,
		UserPlaneConnection: userPlaneConn,
	}

	ue.GTPConnection = append(ue.GTPConnection, gtpConnection)

	// Listen GTP
	if err := n3iwf_data_relay.ListenGTP(userPlaneConn, remoteAddr); err != nil {
		t.Fatal(err)
	}
}
