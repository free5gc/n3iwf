package service

import (
	"bufio"
	"fmt"
	"os/exec"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	aperLogger "github.com/free5gc/aper/logger"
	"github.com/free5gc/n3iwf/internal/logger"
	ngap_service "github.com/free5gc/n3iwf/internal/ngap/service"
	nwucp_service "github.com/free5gc/n3iwf/internal/nwucp/service"
	nwuup_service "github.com/free5gc/n3iwf/internal/nwuup/service"
	"github.com/free5gc/n3iwf/internal/util"
	"github.com/free5gc/n3iwf/pkg/factory"
	ike_service "github.com/free5gc/n3iwf/pkg/ike/service"
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

	n3iwf.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	if _, err := factory.N3iwfConfig.Validate(); err != nil {
		return err
	}

	return nil
}

func (n3iwf *N3IWF) setLogLevel() {
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
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		if errCom := command.Start(); errCom != nil {
			logger.InitLog.Errorf("N3IWF start error: %v", errCom)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
