package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwf/internal/logger"
	ngap_service "github.com/free5gc/n3iwf/internal/ngap/service"
	nwucp_service "github.com/free5gc/n3iwf/internal/nwucp/service"
	nwuup_service "github.com/free5gc/n3iwf/internal/nwuup/service"
	"github.com/free5gc/n3iwf/pkg/app"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	ike_service "github.com/free5gc/n3iwf/pkg/ike/service"
	"github.com/free5gc/n3iwf/pkg/ike/xfrm"
)

var N3IWF *N3iwfApp

var _ app.App = &N3iwfApp{}

type N3iwfApp struct {
	n3iwfCtx *n3iwf_context.N3IWFContext
	cfg      *factory.Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewApp(
	ctx context.Context,
	cfg *factory.Config,
	tlsKeyLogPath string,
) (*N3iwfApp, error) {
	n3iwf := &N3iwfApp{
		cfg: cfg,
		wg:  sync.WaitGroup{},
	}
	n3iwf.ctx, n3iwf.cancel = context.WithCancel(ctx)

	n3iwf.SetLogEnable(cfg.GetLogEnable())
	n3iwf.SetLogLevel(cfg.GetLogLevel())
	n3iwf.SetReportCaller(cfg.GetLogReportCaller())

	n3iwf.n3iwfCtx = n3iwf_context.N3IWFSelf()
	N3IWF = n3iwf
	return n3iwf, nil
}

func (a *N3iwfApp) CancelContext() context.Context {
	return a.ctx
}

func (a *N3iwfApp) Context() *n3iwf_context.N3IWFContext {
	return a.n3iwfCtx
}

func (a *N3iwfApp) Config() *factory.Config {
	return a.cfg
}

func (a *N3iwfApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == io.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(io.Discard)
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

func (a *N3iwfApp) Run() error {
	if !n3iwf_context.InitN3IWFContext() {
		return errors.Errorf("Initicating context failed")
	}

	if err := a.initDefaultXfrmInterface(a.n3iwfCtx); err != nil {
		return err
	}

	a.wg.Add(1)
	go a.listenShutdownEvent()

	// NGAP
	if err := ngap_service.Run(&a.wg); err != nil {
		return errors.Wrapf(err, "Start NGAP service failed")
	}
	logger.MainLog.Infof("NGAP service running.")

	// Relay listeners
	// Control plane
	if err := nwucp_service.Run(&a.wg); err != nil {
		return errors.Wrapf(err, "Listen NWu control plane traffic failed")
	}
	logger.MainLog.Infof("NAS TCP server successfully started.")

	// User plane
	if err := nwuup_service.Run(&a.wg); err != nil {
		return errors.Wrapf(err, "Listen NWu user plane traffic failed")
	}
	logger.MainLog.Infof("Listening NWu user plane traffic")

	// IKE
	if err := ike_service.Run(&a.wg); err != nil {
		return errors.Wrapf(err, "Start IKE service failed")
	}
	logger.MainLog.Infof("IKE service running")

	logger.MainLog.Infof("N3IWF started")

	a.WaitRoutineStopped()
	return nil
}

func (a *N3iwfApp) Start() {
	if err := a.Run(); err != nil {
		logger.MainLog.Errorf("N3IWF Run err: %v", err)
	}
}

func (a *N3iwfApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		a.wg.Done()
	}()

	<-a.ctx.Done()
	a.terminateProcedure()
}

func (a *N3iwfApp) WaitRoutineStopped() {
	a.wg.Wait()
	// Waiting for negotiatioon with netlink for deleting interfaces
	a.removeIPsecInterfaces()
	logger.MainLog.Infof("N3IWF App is terminated")
}

func (a *N3iwfApp) initDefaultXfrmInterface(n3iwfContext *n3iwf_context.N3IWFContext) error {
	// Setup default IPsec interface for Control Plane
	var linkIPSec netlink.Link
	var err error
	n3iwfIPAddr := net.ParseIP(n3iwfContext.IPSecGatewayAddress).To4()
	n3iwfIPAddrAndSubnet := net.IPNet{IP: n3iwfIPAddr, Mask: n3iwfContext.Subnet.Mask}
	newXfrmiName := fmt.Sprintf("%s-default", n3iwfContext.XfrmIfaceName)

	if linkIPSec, err = xfrm.SetupIPsecXfrmi(newXfrmiName, n3iwfContext.XfrmParentIfaceName,
		n3iwfContext.XfrmIfaceId, n3iwfIPAddrAndSubnet); err != nil {
		logger.MainLog.Errorf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
		return err
	}

	route := &netlink.Route{
		LinkIndex: linkIPSec.Attrs().Index,
		Dst:       n3iwfContext.Subnet,
	}

	if err := netlink.RouteAdd(route); err != nil {
		logger.MainLog.Warnf("netlink.RouteAdd: %+v", err)
	}

	logger.MainLog.Infof("Setup XFRM interface %s ", newXfrmiName)

	n3iwfContext.XfrmIfaces.LoadOrStore(n3iwfContext.XfrmIfaceId, linkIPSec)
	n3iwfContext.XfrmIfaceIdOffsetForUP = 1

	return nil
}

func (a *N3iwfApp) removeIPsecInterfaces() {
	a.n3iwfCtx.XfrmIfaces.Range(
		func(key, value interface{}) bool {
			iface := value.(netlink.Link)
			if err := netlink.LinkDel(iface); err != nil {
				logger.MainLog.Errorf("Delete interface %s fail: %+v", iface.Attrs().Name, err)
			} else {
				logger.MainLog.Infof("Delete interface: %s", iface.Attrs().Name)
			}
			return true
		})
}

func (a *N3iwfApp) Terminate() {
	a.cancel()
}

func (a *N3iwfApp) terminateProcedure() {
	logger.MainLog.Info("Stopping service created by N3IWF")

	ngap_service.Stop(a.n3iwfCtx)

	nwucp_service.Stop(a.n3iwfCtx)

	nwuup_service.Stop(a.n3iwfCtx)

	ike_service.Stop(a.n3iwfCtx)
}
