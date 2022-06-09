package address

type CIDR4Reversed struct {
	ip     IP4
	prefix int
	low    IP4
	high   IP4
}

func (cidr CIDR4Reversed) Contains(ip IP4) bool {
	return (ip^cidr.ip)&^(IP4MAX<<cidr.prefix) == 0
}

func NewCIDR4Reversed(s string) CIDR4Reversed {
	ip, prefix := parseCIDR(s, "|")
	return CIDR4Reversed{
		ip:     ip,
		prefix: prefix,
		low:    ip & ^IP4(IP4MAX<<prefix),
		high:   ip | IP4(IP4MAX<<prefix),
	}
}
