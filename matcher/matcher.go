package matcher

type DomainMatcher interface {
	Match(domain string) (match bool, ok bool)
}
