package config

type Conf struct {
	Listen     string
	GFWList    string
	GFWListURL string `toml:"gfwlist_url"`
	GFWb64     bool   `toml:"gfwlist_b64"`
	CNIP       string
	//Logger        *QueryLog `toml:"query_log"`
	HostsFiles    []string `toml:"hosts_files"`
	Hosts         map[string]string
	Cache         CacheConf
	Groups        map[string]*Group
	DisableIPv6   bool     `toml:"disable_ipv6"`
	DisableQTypes []string `toml:"disable_qtypes"`
}

// CacheConf 配置文件中cache section对应的结构
type CacheConf struct {
	Size   int
	MinTTL int `toml:"min_ttl"`
	MaxTTL int `toml:"max_ttl"`
}

// Group 配置文件中每个groups section对应的结构
type Group struct {
	ECS         string
	NoCookie    bool `toml:"no_cookie"`
	Socks5      string
	IPSet       string
	IPSetTTL    int `toml:"ipset_ttl"`
	DNS         []string
	DoT         []string
	DoH         []string
	Concurrent  bool
	FastestV4   bool `toml:"fastest_v4"`
	TCPPingPort int  `toml:"tcp_ping_port"`
	Rules       []string
	RulesFile   string `toml:"rules_file"`
	GFWListMode bool   `toml:"gfwlist_mode"`
}
