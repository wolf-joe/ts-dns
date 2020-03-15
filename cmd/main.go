package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

func main() {
	handler := initConfig()
	srv := &dns.Server{Addr: handler.Listen, Net: "udp", Handler: handler}
	log.Warnf("listen on %s/udp", handler.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen udp error: %v", err)
	}
}
