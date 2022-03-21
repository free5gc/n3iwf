package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/asaskevich/govalidator"
	"github.com/urfave/cli"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/service"
	"github.com/free5gc/util/version"
)

var N3IWF = &service.N3IWF{}

func main() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.AppLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	app := cli.NewApp()
	app.Name = "n3iwf"
	app.Usage = "Non-3GPP Interworking Function (N3IWF)"
	app.Action = action
	app.Flags = N3IWF.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Errorf("N3IWF Run Error: %v\n", err)
	}
}

func action(c *cli.Context) error {
	if err := initLogFile(c.String("log"), c.String("log5gc")); err != nil {
		logger.AppLog.Errorf("%+v", err)
		return err
	}

	if err := N3IWF.Initialize(c); err != nil {
		switch errType := err.(type) {
		case govalidator.Errors:
			validErrs := err.(govalidator.Errors).Errors()
			for _, validErr := range validErrs {
				logger.CfgLog.Errorf("%+v", validErr)
			}
		default:
			logger.CfgLog.Errorf("%+v", errType)
		}
		logger.CfgLog.Errorf("[-- PLEASE REFER TO SAMPLE CONFIG FILE COMMENTS --]")
		return fmt.Errorf("Failed to initialize !!")
	}

	logger.AppLog.Infoln(c.App.Name)
	logger.AppLog.Infoln("N3IWF version: ", version.GetVersion())

	N3IWF.Start()

	return nil
}

func initLogFile(logNfPath, log5gcPath string) error {
	if err := logger.LogFileHook(logNfPath, log5gcPath); err != nil {
		return err
	}
	return nil
}
