package config

type Conf struct {
	HostsFiles []string          `toml:"hosts_files"`
	Hosts      map[string]string `toml:"hosts"`
	Cache      CacheConf         `toml:"cache"`

	Groups        map[string]Group `toml:"groups"`
	DisableIPv6   bool             `toml:"disable_ipv6"`
	DisableQTypes []string         `toml:"disable_qtypes"`

	Listen string `toml:"listen"`
	CNIP   string `toml:"cnip"`
}

// GFWListConf GFW List相关配置
type GFWListConf struct {
	URL     string `toml:"url"`
	File    string `toml:"file"`
	FileB64 bool   `toml:"file_b64"`
}

// CacheConf 配置文件中cache section对应的结构
type CacheConf struct {
	Size   int `toml:"size"`
	MinTTL int `toml:"min_ttl"`
	MaxTTL int `toml:"max_ttl"`
}

// Group 配置文件中每个groups section对应的结构
type Group struct {
	ECS         string   `toml:"ecs"`
	NoCookie    bool     `toml:"no_cookie"`
	Socks5      string   `toml:"socks5"`
	IPSet       string   `toml:"ipset"`
	IPSetTTL    int      `toml:"ipset_ttl"`
	DNS         []string `toml:"dns"`
	DoT         []string `toml:"dot"`
	DoH         []string `toml:"doh"`
	Concurrent  bool     `toml:"concurrent"`
	FastestV4   bool     `toml:"fastest_v4"`
	TCPPingPort int      `toml:"tcp_ping_port"`
	Rules       []string `toml:"rules"`
	RulesFile   string   `toml:"rules_file"`
	GFWListFile string   `toml:"gfwlist_file"`
	GFWListURL  string   `toml:"gfwlist_url"`
	Fallback    bool     `toml:"fallback"`
}

func (g Group) IsSetGFWList() bool {
	return g.GFWListFile != "" || g.GFWListURL != ""
}
