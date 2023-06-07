package service

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwf/internal/logger"
	ngap_service "github.com/free5gc/n3iwf/internal/ngap/service"
	nwucp_service "github.com/free5gc/n3iwf/internal/nwucp/service"
	nwuup_service "github.com/free5gc/n3iwf/internal/nwuup/service"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	ike_service "github.com/free5gc/n3iwf/pkg/ike/service"
	"github.com/free5gc/n3iwf/pkg/ike/xfrm"
)

type N3iwfApp struct {
	cfg      *factory.Config
	n3iwfCtx *n3iwf_context.N3IWFContext
}

func NewApp(cfg *factory.Config) (*N3iwfApp, error) {
	n3iwf := &N3iwfApp{cfg: cfg}
	n3iwf.SetLogEnable(cfg.GetLogEnable())
	n3iwf.SetLogLevel(cfg.GetLogLevel())
	n3iwf.SetReportCaller(cfg.GetLogReportCaller())

	// n3iwf_context.Init()
	n3iwf.n3iwfCtx = n3iwf_context.N3IWFSelf()
	return n3iwf, nil
}

func (a *N3iwfApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == ioutil.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(ioutil.Discard)
	}
}

func (a *N3iwfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *N3iwfApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *N3iwfApp) Start(tlsKeyLogPath string) {
	logger.InitLog.Infoln("Server started")

	var cancel context.CancelFunc
	n3iwfContext := n3iwf_context.N3IWFSelf()
	n3iwfContext.Ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	if !n3iwf_context.InitN3IWFContext() {
		logger.InitLog.Error("Initicating context failed")
		return
	}

	if err := a.InitDefaultXfrmInterface(n3iwfContext); err != nil {
		logger.InitLog.Errorf("Initicating XFRM interface for control plane failed: %+v", err)
		return
	}

	n3iwfContext.Wg.Add(1)
	// Graceful Shutdown
	go a.ListenShutdownEvent(n3iwfContext)

	// NGAP
	if err := ngap_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("Start NGAP service failed: %+v", err)
		return
	}
	logger.InitLog.Info("NGAP service running.")

	// Relay listeners
	// Control plane
	if err := nwucp_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("Listen NWu control plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("NAS TCP server successfully started.")

	// User plane
	if err := nwuup_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("Listen NWu user plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("Listening NWu user plane traffic")

	// IKE
	if err := ike_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("Start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Info("IKE service running.")

	logger.InitLog.Info("N3IWF running...")

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel

	cancel()
	a.WaitRoutineStopped(n3iwfContext)
}

func (a *N3iwfApp) ListenShutdownEvent(n3iwfContext *n3iwf_context.N3IWFContext) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		n3iwfContext.Wg.Done()
	}()

	<-n3iwfContext.Ctx.Done()
	StopServiceConn(n3iwfContext)
}

func (a *N3iwfApp) WaitRoutineStopped(n3iwfContext *n3iwf_context.N3IWFContext) {
	n3iwfContext.Wg.Wait()
	// Waiting for negotiatioon with netlink for deleting interfaces
	a.Terminate(n3iwfContext)
}

func (a *N3iwfApp) InitDefaultXfrmInterface(n3iwfContext *n3iwf_context.N3IWFContext) error {
	// Setup default IPsec interface for Control Plane
	var linkIPSec netlink.Link
	var err error
	n3iwfIPAddr := net.ParseIP(n3iwfContext.IPSecGatewayAddress).To4()
	n3iwfIPAddrAndSubnet := net.IPNet{IP: n3iwfIPAddr, Mask: n3iwfContext.Subnet.Mask}
	newXfrmiName := fmt.Sprintf("%s-default", n3iwfContext.XfrmIfaceName)

	if linkIPSec, err = xfrm.SetupIPsecXfrmi(newXfrmiName, n3iwfContext.XfrmParentIfaceName,
		n3iwfContext.XfrmIfaceId, n3iwfIPAddrAndSubnet); err != nil {
		logger.InitLog.Errorf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
		return err
	}

	route := &netlink.Route{
		LinkIndex: linkIPSec.Attrs().Index,
		Dst:       n3iwfContext.Subnet,
	}

	if err := netlink.RouteAdd(route); err != nil {
		logger.InitLog.Warnf("netlink.RouteAdd: %+v", err)
	}

	logger.InitLog.Infof("Setup XFRM interface %s ", newXfrmiName)

	n3iwfContext.XfrmIfaces.LoadOrStore(n3iwfContext.XfrmIfaceId, linkIPSec)
	n3iwfContext.XfrmIfaceIdOffsetForUP = 1

	return nil
}

func (a *N3iwfApp) RemoveIPsecInterfaces(n3iwfContext *n3iwf_context.N3IWFContext) {
	n3iwfContext.XfrmIfaces.Range(
		func(key, value interface{}) bool {
			iface := value.(netlink.Link)
			if err := netlink.LinkDel(iface); err != nil {
				logger.InitLog.Errorf("Delete interface %s fail: %+v", iface.Attrs().Name, err)
			} else {
				logger.InitLog.Infof("Delete interface: %s", iface.Attrs().Name)
			}
			return true
		})
}

func (a *N3iwfApp) Terminate(n3iwfContext *n3iwf_context.N3IWFContext) {
	logger.InitLog.Info("Terminating N3IWF...")
	logger.InitLog.Info("Deleting interfaces created by N3IWF")
	a.RemoveIPsecInterfaces(n3iwfContext)
	logger.InitLog.Info("N3IWF terminated")
}

func StopServiceConn(n3iwfContext *n3iwf_context.N3IWFContext) {
	logger.InitLog.Info("Stopping service created by N3IWF")

	ngap_service.Stop(n3iwfContext)

	nwucp_service.Stop(n3iwfContext)

	nwuup_service.Stop(n3iwfContext)

	ike_service.Stop(n3iwfContext)
}
