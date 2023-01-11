package config

type Conf struct {
	HostsFiles []string          `toml:"hosts_files"`
	Hosts      map[string]string `toml:"hosts"`
	Cache      CacheConf         `toml:"cache"`

	Groups        map[string]Group          `toml:"groups"`
	DisableIPv6   bool                      `toml:"disable_ipv6"`
	DisableQTypes []string                  `toml:"disable_qtypes"`
	Redirectors   map[string]RedirectorConf `toml:"redirectors"`

	Listen string `toml:"listen"`
}

// CacheConf 配置文件中cache section对应的结构
type CacheConf struct {
	Size   int `toml:"size"`
	MinTTL int `toml:"min_ttl"`
	MaxTTL int `toml:"max_ttl"`
}

// Group 配置文件中每个groups section对应的结构
type Group struct {
	DisableIPv6   bool     `toml:"disable_ipv6"`
	DisableQTypes []string `toml:"disable_qtypes"`
	ECS           string   `toml:"ecs"`
	NoCookie      bool     `toml:"no_cookie"`

	Rules       []string `toml:"rules"`
	RulesFile   string   `toml:"rules_file"`
	GFWListFile string   `toml:"gfwlist_file"`
	GFWListURL  string   `toml:"gfwlist_url"`
	Fallback    bool     `toml:"fallback"`

	Socks5 string   `toml:"socks5"`
	DNS    []string `toml:"dns"`
	DoT    []string `toml:"dot"`
	DoH    []string `toml:"doh"`

	Concurrent  bool `toml:"concurrent"`
	FastestV4   bool `toml:"fastest_v4"`
	TCPPingPort int  `toml:"tcp_ping_port"`

	IPSet    string `toml:"ipset"`
	IPSetTTL int    `toml:"ipset_ttl"`

	Redirector string `toml:"redirector"`
}

func (g Group) IsSetGFWList() bool {
	return g.GFWListFile != "" || g.GFWListURL != ""
}

func (g Group) IsEmptyRule() bool {
	return len(g.Rules) == 0 && g.RulesFile == "" && !g.IsSetGFWList()
}

// RedirectorConf 重定向器配置
type RedirectorConf struct {
	Type      string   `toml:"type"`
	Rules     []string `toml:"rules"`
	RulesFile string   `toml:"rules_file"`
	DstGroup  string   `toml:"dst_group"`
}
