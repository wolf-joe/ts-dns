package config

type Conf struct {
	Listen  string
	GFWList string
	GFWb64  bool `toml:"gfwlist_b64"`
	CNIP    string
	//Logger        *QueryLog `toml:"query_log"`
	HostsFiles []string `toml:"hosts_files"`
	Hosts      map[string]string
	//Cache         CacheConf
	//Groups        map[string]*Group
	DisableIPv6   bool     `toml:"disable_ipv6"`
	DisableQTypes []string `toml:"disable_qtypes"`
}
