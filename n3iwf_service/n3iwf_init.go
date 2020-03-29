package n3iwf_service

import (
	"bufio"
	"fmt"
	"os/exec"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"gofree5gc/lib/path_util"
	"gofree5gc/src/app"
	"gofree5gc/src/n3iwf/factory"
	"gofree5gc/src/n3iwf/logger"
	"gofree5gc/src/n3iwf/n3iwf_data_relay"
	"gofree5gc/src/n3iwf/n3iwf_handler"
	"gofree5gc/src/n3iwf/n3iwf_ike/udp_server"
	"gofree5gc/src/n3iwf/n3iwf_ngap/n3iwf_sctp"
	"gofree5gc/src/n3iwf/n3iwf_util"
	//"gofree5gc/src/n3iwf/n3iwf_context"
)

type N3IWF struct{}

type (
	// Config information.
	Config struct {
		n3iwfcfg string
	}
)

var config Config

var n3iwfCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "free5gccfg",
		Usage: "common config file",
	},
	cli.StringFlag{
		Name:  "n3iwfcfg",
		Usage: "n3iwf config file",
	},
}

var initLog *logrus.Entry

func init() {
	initLog = logger.InitLog
}

func (*N3IWF) GetCliCmd() (flags []cli.Flag) {
	return n3iwfCLi
}

func (*N3IWF) Initialize(c *cli.Context) {

	config = Config{
		n3iwfcfg: c.String("n3iwfcfg"),
	}

	if config.n3iwfcfg != "" {
		factory.InitConfigFactory(path_util.Gofree5gcPath(config.n3iwfcfg))
	} else {
		DefaultSmfConfigPath := path_util.Gofree5gcPath("gofree5gc/config/n3iwfcfg.conf")
		factory.InitConfigFactory(DefaultSmfConfigPath)
	}

	initLog.Traceln("N3IWF debug level(string):", app.ContextSelf().Logger.N3IWF.DebugLevel)
	if app.ContextSelf().Logger.N3IWF.DebugLevel != "" {
		initLog.Infoln("W3IWF debug level(string):", app.ContextSelf().Logger.N3IWF.DebugLevel)
		level, err := logrus.ParseLevel(app.ContextSelf().Logger.N3IWF.DebugLevel)
		if err == nil {
			logger.SetLogLevel(level)
		}
	}

	logger.SetReportCaller(app.ContextSelf().Logger.N3IWF.ReportCaller)

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
	initLog.Infoln("Server started")

	if !n3iwf_util.InitN3IWFContext() {
		initLog.Error("Initicating context failed")
	}

	wg := sync.WaitGroup{}

	// N3IWF handler
	go n3iwf_handler.Handle()
	wg.Add(1)

	// NGAP
	n3iwf_sctp.InitiateSCTP(&wg)

	// Relay listeners
	// Control plane
	if err := n3iwf_data_relay.SetupNASTCPServer(); err != nil {
		initLog.Errorf("Listen N1 control plane traffic failed: %+v", err)
	} else {
		initLog.Info("NAS TCP server successfully started.")
	}
	// User plane
	if err := n3iwf_data_relay.ListenN1UPTraffic(); err != nil {
		initLog.Errorf("Listen N1 user plane traffic failed: %+v", err)
		return
	} else {
		initLog.Info("Listening N1 user plane traffic")
	}
	wg.Add(2)

	// IKE
	udp_server.Run()
	wg.Add(1)

	wg.Wait()

}

func (n3iwf *N3IWF) Exec(c *cli.Context) error {

	//N3IWF.Initialize(cfgPath, c)

	initLog.Traceln("args:", c.String("n3iwfcfg"))
	args := n3iwf.FilterCli(c)
	initLog.Traceln("filter: ", args)
	command := exec.Command("./n3iwf", args...)

	wg := sync.WaitGroup{}
	wg.Add(3)

	stdout, err := command.StdoutPipe()
	if err != nil {
		initLog.Fatalln(err)
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
		initLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		if err := command.Start(); err != nil {
			initLog.Errorf("N3IWF start error: %v", err)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
