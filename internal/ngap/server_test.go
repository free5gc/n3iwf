package ngap

import (
	"context"
	"sync"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/ike"
	"github.com/free5gc/n3iwf/pkg/factory"
)

type n3iwfTestApp struct {
	cfg      *factory.Config
	n3iwfCtx *n3iwf_context.N3IWFContext
	ctx      context.Context
	cancel   context.CancelFunc
	wg       *sync.WaitGroup

	ngapServer *Server
	ikeServer  *ike.Server

	mockIkeEvtCh *n3iwf_context.SafeEvtCh[n3iwf_context.IkeEvt]
}

func (a *n3iwfTestApp) Config() *factory.Config {
	return a.cfg
}

func (a *n3iwfTestApp) Context() *n3iwf_context.N3IWFContext {
	return a.n3iwfCtx
}

func (a *n3iwfTestApp) CancelContext() context.Context {
	return a.ctx
}

func (a *n3iwfTestApp) SendNgapEvt(evt n3iwf_context.NgapEvt) error {
	return a.ngapServer.SendNgapEvt(evt)
}

func (a *n3iwfTestApp) SendIkeEvt(evt n3iwf_context.IkeEvt) error {
	return a.mockIkeEvtCh.SendEvt(evt)
}

func NewN3iwfTestApp(cfg *factory.Config) (*n3iwfTestApp, error) {
	var err error
	ctx, cancel := context.WithCancel(context.Background())

	n3iwfApp := &n3iwfTestApp{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		wg:     &sync.WaitGroup{},
	}
	n3iwfApp.mockIkeEvtCh = new(n3iwf_context.SafeEvtCh[n3iwf_context.IkeEvt])
	n3iwfApp.mockIkeEvtCh.Init(make(chan n3iwf_context.IkeEvt, 10))

	n3iwfApp.n3iwfCtx, err = n3iwf_context.NewTestContext(n3iwfApp)
	if err != nil {
		return nil, err
	}
	return n3iwfApp, err
}
