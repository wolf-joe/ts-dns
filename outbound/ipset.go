package outbound

import "github.com/wolf-joe/go-ipset/ipset"

type iIPSet interface {
	Add(entry string, timeout int) error
	GetName() string
	GetTimeout() int
}

type ipSetWrapper struct {
	*ipset.IPSet
}

func (i ipSetWrapper) GetName() string { return i.Name }
func (i ipSetWrapper) GetTimeout() int { return i.Timeout }

var (
	_ iIPSet = ipSetWrapper{}
)
