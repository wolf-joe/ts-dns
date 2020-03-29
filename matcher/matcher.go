package matcher

// DomainMatcher 域名匹配器基类
type DomainMatcher interface {
	Match(domain string) (match bool, ok bool)
}
