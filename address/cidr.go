package address

import (
	"strconv"
	"strings"
)

type CIDR4 struct {
	ip     IP4
	prefix int
	low    IP4
	high   IP4
}

func (cidr CIDR4) Contains(ip IP4) bool {
	return (ip^cidr.ip)&^(IP4MAX>>cidr.prefix) == 0
}

func NewCIDR4(s string) CIDR4 {
	ip, prefix := parseCIDR(s, "/")
	return CIDR4{
		ip:     ip,
		prefix: prefix,
		low:    ip & ^IP4(^IP4MAX>>prefix),
		high:   ip | IP4(IP4MAX>>prefix),
	}
}

func parseCIDR(s string, separator string) (ip IP4, prefix int) {
	parts := strings.SplitN(s, separator, 2)
	ip = NewIP4(parts[0])
	prefix, err := strconv.Atoi(parts[1])
	if err != nil || prefix > 32 || prefix < 0 {
		panic("invalid prefix: " + parts[1])
	}
	return ip, prefix
}
