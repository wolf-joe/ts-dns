package matcher

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

var text = `[AutoProxy]
!comment
|http://1.1.1.1
unknown

|https://*.youtube.com/path
.abc.com
@@||cip.cc
@@||*.cn
/^https?:\/\/([^\/]+\.)*google\.(ac|ad|ae|af|al|am|as|at|az|ba|be|bf|bg|bi|bj|bs|bt|by|ca|cat|cd|cf|cg|ch|ci|cl|cm|co.ao|co.bw|co.ck|co.cr|co.id|co.il|co.in|co.jp|co.ke|co.kr|co.ls|co.ma|com|com.af|com.ag|com.ai|com.ar|com.au|com.bd|com.bh|com.bn|com.bo|com.br|com.bz|com.co|com.cu|com.cy|com.do|com.ec|com.eg|com.et|com.fj|com.gh|com.gi|com.gt|com.hk|com.jm|com.kh|com.kw|com.lb|com.ly|com.mm|com.mt|com.mx|com.my|com.na|com.nf|com.ng|com.ni|com.np|com.om|com.pa|com.pe|com.pg|com.ph|com.pk|com.pr|com.py|com.qa|com.sa|com.sb|com.sg|com.sl|com.sv|com.tj|com.tr|com.tw|com.ua|com.uy|com.vc|com.vn|co.mz|co.nz|co.th|co.tz|co.ug|co.uk|co.uz|co.ve|co.vi|co.za|co.zm|co.zw|cv|cz|de|dj|dk|dm|dz|ee|es|eu|fi|fm|fr|ga|ge|gg|gl|gm|gp|gr|gy|hk|hn|hr|ht|hu|ie|im|iq|is|it|it.ao|je|jo|kg|ki|kz|la|li|lk|lt|lu|lv|md|me|mg|mk|ml|mn|ms|mu|mv|mw|mx|ne|nl|no|nr|nu|org|pl|pn|ps|pt|ro|rs|ru|rw|sc|se|sh|si|sk|sm|sn|so|sr|st|td|tg|tk|tl|tm|tn|to|tt|us|vg|vn|vu|ws)\/.*/
`

func TestNewChecker(t *testing.T) {
	filename := "go_test_adblock.txt"
	// 文件不存在
	matcher, err := NewABPByFile(filename, false)
	assert.NotEqual(t, err, nil)
	// 写入不正确内容
	content := base64.StdEncoding.EncodeToString([]byte(text)) + "???"
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	// 读取失败
	matcher, err = NewABPByFile(filename, true)
	assert.NotEqual(t, err, nil)
	// 写入正确内容
	content = base64.StdEncoding.EncodeToString([]byte(text))
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	// 读取成功
	matcher, err = NewABPByFile(filename, true)
	assert.NotEqual(t, matcher, nil)
	assert.Equal(t, err, nil)
	// 移除生成的文件
	_ = os.Remove(filename)

	// 判断空串
	_, ok := matcher.Match("")
	assert.Equal(t, ok, false)
	// 规则.abc.com不匹配abc.com
	_, ok = matcher.Match("abc.com")
	assert.Equal(t, ok, false)
	// 但匹配test.abc.com
	_, ok = matcher.Match("test.abc.com")
	assert.Equal(t, ok, true)
	// 匹配白名单@@||cip.cc
	matched, ok := matcher.Match("cip.cc.")
	assert.Equal(t, ok, true)
	assert.Equal(t, matched, false)
	// 匹配白名单@@||*.cn
	matched, ok = matcher.Match("ip.cn")
	assert.Equal(t, ok, true)
	assert.Equal(t, matched, false)
	// 匹配通配符*.youtube.*
	matched, ok = matcher.Match("www.youtube.com")
	assert.Equal(t, ok, true)
	assert.Equal(t, matched, true)
	// 匹配google正则
	matched, ok = matcher.Match("google.com")
	assert.Equal(t, matched, true)
	assert.Equal(t, ok, true)
}
