package outbound

import (
	"context"
	"encoding/base64"
	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/matcher"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net"
	"net/http"
	"sync/atomic"
	"time"
	"unsafe"
)

type IGroup interface {
	Match(req *dns.Msg) bool
	Handle(req *dns.Msg) *dns.Msg
	Start()
	Stop()
}

func BuildGroups(conf *config.Conf) (map[string]IGroup, error) {
	//TODO implement me
	panic("implement me")
}

var (
	_ IGroup = &groupImpl{}
)

type groupImpl struct {
	matchers   []matcher.DomainMatcher
	gfwList    unsafe.Pointer // type: *matcher.ABPlus
	gfwListURL string
	proxy      proxy.Dialer
	client     *dns.Client
	callers    []Caller

	stopCh  chan struct{}
	stopped chan struct{}
}

func (g *groupImpl) Match(req *dns.Msg) bool {
	domain := ""
	if len(req.Question) > 0 {
		domain = req.Question[0].Name
	}
	if domain == "" {
		return false
	}
	for _, m := range g.matchers {
		if match, _ := m.Match(domain); match {
			return true
		}
	}
	if ptr := atomic.LoadPointer(&g.gfwList); ptr != nil {
		if match, _ := (*matcher.ABPlus)(ptr).Match(domain); match {
			return true
		}
	}
	return false
}

func (g *groupImpl) Handle(req *dns.Msg) *dns.Msg {
	//TODO implement me
	panic("implement me")
}

func (g *groupImpl) Start() {
	if g.gfwList != nil && g.gfwListURL != "" {
		// grab gfw list online
		client := new(http.Client)
		client.Timeout = 10 * time.Second
		if g.proxy != nil {
			wrap := func(ctx context.Context, network, addr string) (net.Conn, error) {
				return g.proxy.Dial(network, addr)
			}
			client.Transport = &http.Transport{DialContext: wrap}
		}
		req, _ := http.NewRequest("GET", g.gfwListURL, nil)
		getGFWList := func() *matcher.ABPlus {
			resp, err := client.Do(req)
			if err != nil {
				logrus.Warnf("get gfw list %q failed: %+v", g.gfwListURL, err)
				return nil
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				logrus.Warnf("get gfw list %q failed, status_code: %d", g.gfwListURL, resp.StatusCode)
				return nil
			}
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				logrus.Warnf("read gfw list %q failed, error: %+v", g.gfwListURL, err)
				return nil
			}
			dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
			if _, err = base64.StdEncoding.Decode(data, dst); err != nil {
				logrus.Warnf("decode gfw list %q failed, error: %+v", g.gfwListURL, err)
				return nil
			}
			return matcher.NewABPByText(string(dst))
		}

		lastSuccess := time.Unix(0, 0)
		tick := time.Tick(time.Minute)
		go func() {
			for {
				select {
				case <-tick:
					if time.Now().Sub(lastSuccess).Hours() < 1 {
						// every hour
						continue
					}
					if m := getGFWList(); m != nil {
						atomic.StorePointer(&g.gfwList, unsafe.Pointer(m))
						lastSuccess = time.Now()
					}
				case <-g.stopCh:
					close(g.stopped)
					return
				}
			}
		}()
	}
}

func (g *groupImpl) Stop() {
	close(g.stopCh)
	<-g.stopped
}
