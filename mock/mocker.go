package mock

import (
	"github.com/agiledragon/gomonkey"
	"reflect"
)

// gomonkey的封装
type Mocker struct {
	patches []*gomonkey.Patches
}

// gomonkey.ApplyFuncSeq的封装
func (m *Mocker) FuncSeq(target interface{}, outputs []gomonkey.Params) {
	var cells []gomonkey.OutputCell
	for _, output := range outputs {
		cells = append(cells, gomonkey.OutputCell{Values: output})
	}
	m.patches = append(m.patches, gomonkey.ApplyFuncSeq(target, cells))
}

// gomonkey.ApplyMethodSeq的封装
func (m *Mocker) MethodSeq(target interface{}, method string, outputs []gomonkey.Params) {
	var cells []gomonkey.OutputCell
	for _, output := range outputs {
		cells = append(cells, gomonkey.OutputCell{Values: output})
	}
	p := gomonkey.ApplyMethodSeq(reflect.TypeOf(target), method, cells)
	m.patches = append(m.patches, p)
}

// Reset所有mock
func (m *Mocker) Reset() {
	for _, patches := range m.patches {
		patches.Reset()
	}
	m.patches = []*gomonkey.Patches{}
}

func NewMocker() *Mocker {
	return &Mocker{patches: []*gomonkey.Patches{}}
}
