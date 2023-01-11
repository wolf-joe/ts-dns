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
	_ iIPSet = MockIPSet{}
)

type MockIPSet struct {
	Name    string
	Timeout int
	MockAdd func(entry string, timeout int) error
}

func (i MockIPSet) GetName() string                     { return i.Name }
func (i MockIPSet) GetTimeout() int                     { return i.Timeout }
func (i MockIPSet) Add(entry string, timeout int) error { return i.MockAdd(entry, timeout) }
