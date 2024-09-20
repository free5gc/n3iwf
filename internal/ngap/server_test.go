package ngap

import (
	"context"
	"sync"

	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/n3iwf/pkg/ike"
)

type n3iwfTestApp struct {
	cfg        *factory.Config
	n3iwfCtx   *n3iwf_context.N3IWFContext
	ngapServer *Server
	ikeServer  *ike.Server
	ctx        context.Context
	cancel     context.CancelFunc
	wg         *sync.WaitGroup
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

func (a *n3iwfTestApp) NgapEvtCh() chan n3iwf_context.NgapEvt {
	return a.ngapServer.RcvEventCh
}

func (a *n3iwfTestApp) IkeEvtCh() chan n3iwf_context.IkeEvt {
	return a.ikeServer.RcvEventCh
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

	n3iwfApp.n3iwfCtx, err = n3iwf_context.NewTestContext(n3iwfApp)
	if err != nil {
		return nil, err
	}
	return n3iwfApp, err
}
