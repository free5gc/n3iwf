package n3iwf_data_relay_test

import (
	"gofree5gc/src/n3iwf/n3iwf_context"
	"gofree5gc/src/n3iwf/n3iwf_data_relay"
	"gofree5gc/src/n3iwf/n3iwf_handler"
	"sync"
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

	go n3iwf_handler.Handle()

	// Add UE inner IP to context
	ue.IPSecInnerIP = "10.0.0.2"
	n3iwfSelf.AllocatedUEIPAddress["10.0.0.2"] = ue

	n3iwfSelf.GTPBindAddress = "172.31.0.153"

	gtpConnection, err := n3iwf_data_relay.SetupGTP("172.31.0.152")
	if err != nil {
		t.Fatal(err)
	}

	ueTEID := n3iwfSelf.NewTEID(ue)

	gtpConnection.IncomingTEID = ueTEID
	gtpConnection.OutgoingTEID = 1

	ue.GTPConnection = append(ue.GTPConnection, gtpConnection)

	// Listen GTP
	if err := n3iwf_data_relay.ListenGTP(gtpConnection.UserPlaneConnection); err != nil {
		t.Fatal(err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
}
