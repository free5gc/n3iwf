package n3iwf_context

import (
	"fmt"
	"github.com/sirupsen/logrus"

	"gofree5gc/src/n3iwf/logger"
)

var contextLog *logrus.Entry

var n3iwfContext = N3IWFContext{}
var ranUeNgapIdGenerator int64 = 0

type N3IWFContext struct {
	NFInfo                 N3IWFNFInfo
	UePool                 map[int64]*N3IWFUe   // RanUeNgapID as key
	AMFPool                map[string]*N3IWFAMF // SCTPAddr as key
	AMFReInitAvailableList map[string]bool      //SCTPAddr as key
}

func init() {
	// init log
	contextLog = logger.ContextLog

	// init context
	N3IWFSelf().UePool = make(map[int64]*N3IWFUe)
	N3IWFSelf().AMFPool = make(map[string]*N3IWFAMF)
	N3IWFSelf().AMFReInitAvailableList = make(map[string]bool)
}

// Create new N3IWF context
func N3IWFSelf() *N3IWFContext {
	return &n3iwfContext
}

func (context *N3IWFContext) NewN3iwfUe() *N3IWFUe {
	n3iwfUe := &N3IWFUe{}
	n3iwfUe.init()

	ranUeNgapIdGenerator %= MaxValueOfRanUeNgapID
	ranUeNgapIdGenerator++
	for {
		if _, double := context.UePool[ranUeNgapIdGenerator]; double {
			ranUeNgapIdGenerator++
		} else {
			break
		}
	}

	n3iwfUe.RanUeNgapId = ranUeNgapIdGenerator
	n3iwfUe.AmfUeNgapId = AmfUeNgapIdUnspecified
	context.UePool[n3iwfUe.RanUeNgapId] = n3iwfUe
	return n3iwfUe
}

func (context *N3IWFContext) NewN3iwfAmf(sctpAddr string) *N3IWFAMF {
	if amf, ok := context.AMFPool[sctpAddr]; ok {
		contextLog.Warn("[Context] NewN3iwfAmf(): AMF entry already exists.")
		return amf
	} else {
		amf = &N3IWFAMF{
			SCTPAddr:              sctpAddr,
			N3iwfUeList:           make(map[int64]*N3IWFUe),
			AMFTNLAssociationList: make(map[string]*AMFTNLAssociationItem),
		}
		context.AMFPool[sctpAddr] = amf
		return amf
	}
}

func (context *N3IWFContext) FindAMFBySCTPAddr(sctpAddr string) (*N3IWFAMF, error) {
	amf, ok := context.AMFPool[sctpAddr]
	if !ok {
		return nil, fmt.Errorf("[Context] FindAMF(): AMF not found. sctpAddr: %s", sctpAddr)
	}
	return amf, nil
}

func (context *N3IWFContext) FindUeByRanUeNgapID(ranUeNgapID int64) *N3IWFUe {
	if n3iwfUE, ok := context.UePool[ranUeNgapID]; ok {
		return n3iwfUE
	} else {
		return nil
	}
}

// returns true means reinitialization is available, and false is unavailable.
func (context *N3IWFContext) CheckAMFReInit(sctpAddr string) bool {

	if check, ok := context.AMFReInitAvailableList[sctpAddr]; ok {
		return check
	}
	return true
}
