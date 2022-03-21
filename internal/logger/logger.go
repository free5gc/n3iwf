package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	aperLogger "github.com/free5gc/aper/logger"
	ngapLogger "github.com/free5gc/ngap/logger"
	logger_util "github.com/free5gc/util/logger"
)

var log *logrus.Logger

var (
	AppLog     *logrus.Entry
	InitLog    *logrus.Entry
	CfgLog     *logrus.Entry
	ContextLog *logrus.Entry
	NgapLog    *logrus.Entry
	IKELog     *logrus.Entry
	GTPLog     *logrus.Entry
	NWuCPLog   *logrus.Entry
	NWuUPLog   *logrus.Entry
	RelayLog   *logrus.Entry
	UtilLog    *logrus.Entry
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	AppLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "Init"})
	CfgLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "CFG"})
	ContextLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "Context"})
	NgapLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "NGAP"})
	IKELog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "IKE"})
	GTPLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "GTP"})
	NWuCPLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "NWuCP"})
	NWuUPLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "NWuUP"})
	RelayLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "Relay"})
	UtilLog = log.WithFields(logrus.Fields{"component": "N3IWF", "category": "Util"})
}

func LogFileHook(logNfPath string, log5gcPath string) error {
	if fullPath, err := logger_util.CreateFree5gcLogFile(log5gcPath); err == nil {
		if fullPath != "" {
			free5gcLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
			if hookErr != nil {
				return hookErr
			}
			log.Hooks.Add(free5gcLogHook)
			aperLogger.GetLogger().Hooks.Add(free5gcLogHook)
			ngapLogger.GetLogger().Hooks.Add(free5gcLogHook)
		}
	} else {
		return err
	}

	if fullPath, err := logger_util.CreateNfLogFile(logNfPath, "n3iwf.log"); err == nil {
		selfLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
		if hookErr != nil {
			return hookErr
		}
		log.Hooks.Add(selfLogHook)
		aperLogger.GetLogger().Hooks.Add(selfLogHook)
		ngapLogger.GetLogger().Hooks.Add(selfLogHook)
	} else {
		return err
	}

	return nil
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(enable bool) {
	log.SetReportCaller(enable)
}
