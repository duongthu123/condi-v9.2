package main

import (
	"net"
	"net/url"
	"strings"  

	dns "github.com/bogdanovich/dns_resolver"
)

var resolver *dns.DnsResolver = nil

// CanAttack will return true if the target is valid
func CanAttack(addr string) (int, bool) {
	types := 0
	if IsIP(addr) {
		if IsIPv6(addr) {
			types = 4
		} else {
			types = 1
		}
		return types, true
	} else if IsURL(addr) {
		types = 2
		return types, true
	} else if IsDomain(addr) {
		types = 3
		return types, true
	}

	return 0, false
}
// IsIP will check if the address is a valid IP address
func IsIP(addr string) bool {
	return net.ParseIP(addr) != nil
}

// IsURL will check if the address is a valid URL
func IsURL(addr string) bool {
	u, err := url.ParseRequestURI(addr)
	
	return u != nil && err == nil
}

func IsDomain(addr string) bool {
	ips, _ := resolver.LookupHost(addr)
	return len(ips) > 0
}
func IsIPv6(addr string) bool {
	return net.ParseIP(addr) != nil && strings.Contains(addr, ":")
}
// OnStart will start the DNS
func OnStart() {
	resolver = dns.New([]string{"1.1.1.1", "8.8.8.8"})
}