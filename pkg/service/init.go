package service

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"

	aperLogger "github.com/free5gc/aper/logger"
	"github.com/free5gc/n3iwf/internal/logger"
	ngap_service "github.com/free5gc/n3iwf/internal/ngap/service"
	nwucp_service "github.com/free5gc/n3iwf/internal/nwucp/service"
	nwuup_service "github.com/free5gc/n3iwf/internal/nwuup/service"
	"github.com/free5gc/n3iwf/internal/util"
	"github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	ike_service "github.com/free5gc/n3iwf/pkg/ike/service"
	"github.com/free5gc/n3iwf/pkg/ike/xfrm"
	ngapLogger "github.com/free5gc/ngap/logger"
)

type N3IWF struct{}

type (
	// Commands information.
	Commands struct {
		config string
	}
)

var commands Commands

var cliCmd = []cli.Flag{
	cli.StringFlag{
		Name:  "config, c",
		Usage: "Load configuration from `FILE`",
	},
	cli.StringFlag{
		Name:  "log, l",
		Usage: "Output NF log to `FILE`",
	},
	cli.StringFlag{
		Name:  "log5gc, lc",
		Usage: "Output free5gc log to `FILE`",
	},
}

func (*N3IWF) GetCliCmd() (flags []cli.Flag) {
	return cliCmd
}

func (n3iwf *N3IWF) Initialize(c *cli.Context) error {
	commands = Commands{
		config: c.String("config"),
	}

	if commands.config != "" {
		if err := factory.InitConfigFactory(commands.config); err != nil {
			return err
		}
	} else {
		if err := factory.InitConfigFactory(util.N3iwfDefaultConfigPath); err != nil {
			return err
		}
	}

	n3iwf.SetLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	if _, err := factory.N3iwfConfig.Validate(); err != nil {
		return err
	}

	return nil
}

func (n3iwf *N3IWF) SetLogLevel() {
	if factory.N3iwfConfig.Logger == nil {
		logger.InitLog.Warnln("N3IWF config without log level setting!!!")
		return
	}

	if factory.N3iwfConfig.Logger.N3IWF != nil {
		if factory.N3iwfConfig.Logger.N3IWF.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.N3iwfConfig.Logger.N3IWF.DebugLevel); err != nil {
				logger.InitLog.Warnf("N3IWF Log level [%s] is invalid, set to [info] level",
					factory.N3iwfConfig.Logger.N3IWF.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				logger.InitLog.Infof("N3IWF Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Infoln("N3IWF Log level is default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(factory.N3iwfConfig.Logger.N3IWF.ReportCaller)
	}

	if factory.N3iwfConfig.Logger.NGAP != nil {
		if factory.N3iwfConfig.Logger.NGAP.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.N3iwfConfig.Logger.NGAP.DebugLevel); err != nil {
				ngapLogger.NgapLog.Warnf("NGAP Log level [%s] is invalid, set to [info] level",
					factory.N3iwfConfig.Logger.NGAP.DebugLevel)
				ngapLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				ngapLogger.SetLogLevel(level)
			}
		} else {
			ngapLogger.NgapLog.Warnln("NGAP Log level not set. Default set to [info] level")
			ngapLogger.SetLogLevel(logrus.InfoLevel)
		}
		ngapLogger.SetReportCaller(factory.N3iwfConfig.Logger.NGAP.ReportCaller)
	}

	if factory.N3iwfConfig.Logger.Aper != nil {
		if factory.N3iwfConfig.Logger.Aper.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.N3iwfConfig.Logger.Aper.DebugLevel); err != nil {
				aperLogger.AperLog.Warnf("Aper Log level [%s] is invalid, set to [info] level",
					factory.N3iwfConfig.Logger.Aper.DebugLevel)
				aperLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				aperLogger.SetLogLevel(level)
			}
		} else {
			aperLogger.AperLog.Warnln("Aper Log level not set. Default set to [info] level")
			aperLogger.SetLogLevel(logrus.InfoLevel)
		}
		aperLogger.SetReportCaller(factory.N3iwfConfig.Logger.Aper.ReportCaller)
	}
}

func (n3iwf *N3IWF) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range n3iwf.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (n3iwf *N3IWF) Start() {
	logger.InitLog.Infoln("Server started")

	if !util.InitN3IWFContext() {
		logger.InitLog.Error("Initicating context failed")
		return
	}

	if err := n3iwf.InitDefaultXfrmInterface(); err != nil {
		logger.InitLog.Errorf("Initicating XFRM interface for control plane failed: %+v", err)
		return
	}

	// Graceful Shutdown
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		<-signalChannel
		n3iwf.Terminate()
		// Waiting for negotiatioon with netlink for deleting interfaces
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	wg := sync.WaitGroup{}

	// NGAP
	if err := ngap_service.Run(); err != nil {
		logger.InitLog.Errorf("Start NGAP service failed: %+v", err)
		return
	}
	logger.InitLog.Info("NGAP service running.")
	wg.Add(1)

	// Relay listeners
	// Control plane
	if err := nwucp_service.Run(); err != nil {
		logger.InitLog.Errorf("Listen NWu control plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("NAS TCP server successfully started.")
	wg.Add(1)

	// User plane
	if err := nwuup_service.Run(); err != nil {
		logger.InitLog.Errorf("Listen NWu user plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("Listening NWu user plane traffic")
	wg.Add(1)

	// IKE
	if err := ike_service.Run(); err != nil {
		logger.InitLog.Errorf("Start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Info("IKE service running.")
	wg.Add(1)

	logger.InitLog.Info("N3IWF running...")

	wg.Wait()
}

func (n3iwf *N3IWF) InitDefaultXfrmInterface() error {
	n3iwfContext := context.N3IWFSelf()

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

func (n3iwf *N3IWF) RemoveIPsecInterfaces() {
	n3iwfSelf := context.N3IWFSelf()
	n3iwfSelf.XfrmIfaces.Range(
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

func (n3iwf *N3IWF) Terminate() {
	logger.InitLog.Info("Terminating N3IWF...")
	logger.InitLog.Info("Deleting interfaces created by N3IWF")
	n3iwf.RemoveIPsecInterfaces()
	logger.InitLog.Info("N3IWF terminated")
}

func (n3iwf *N3IWF) Exec(c *cli.Context) error {
	// N3IWF.Initialize(cfgPath, c)

	logger.InitLog.Traceln("args:", c.String("n3iwfcfg"))
	args := n3iwf.FilterCli(c)
	logger.InitLog.Traceln("filter: ", args)
	command := exec.Command("./n3iwf", args...)

	wg := sync.WaitGroup{}
	wg.Add(3)

	stdout, err := command.StdoutPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		if errCom := command.Start(); errCom != nil {
			logger.InitLog.Errorf("N3IWF start error: %v", errCom)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
