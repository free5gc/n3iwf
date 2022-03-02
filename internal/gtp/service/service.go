package service

import (
	"context"
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	gtp "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"

	"github.com/free5gc/n3iwf/internal/gtp/handler"
	"github.com/free5gc/n3iwf/internal/logger"
	n3iwfContext "github.com/free5gc/n3iwf/pkg/context"
)

var gtpLog *logrus.Entry

var gtpContext context.Context

func init() {
	gtpLog = logger.GTPLog
	gtpContext = context.TODO()
}

// SetupGTPTunnelWithUPF set up GTP connection with UPF
// return *gtp.UPlaneConn, net.Addr and error
func SetupGTPTunnelWithUPF(upfIPAddr string) (*gtp.UPlaneConn, net.Addr, error) {
	n3iwfSelf := n3iwfContext.N3IWFSelf()

	// Set up GTP connection
	upfUDPAddr := upfIPAddr + gtp.GTPUPort

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", upfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", upfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	n3iwfUDPAddr := n3iwfSelf.GTPBindAddress + gtp.GTPUPort

	localUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", n3iwfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	// Dial to UPF
	userPlaneConnection, err := gtp.DialUPlane(gtpContext, localUDPAddr, remoteUDPAddr)
	if err != nil {
		gtpLog.Errorf("Dial to UPF failed: %+v", err)
		return nil, nil, errors.New("Dial failed")
	}

	// Overwrite T-PDU handler for supporting extension header containing QoS parameters
	userPlaneConnection.AddHandler(gtpMsg.MsgTypeTPDU, handler.HandleQoSTPDU)

	return userPlaneConnection, remoteUDPAddr, nil
}
