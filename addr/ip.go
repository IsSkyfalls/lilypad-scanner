package addr

import (
	"encoding/binary"
	"net"
)

type IP4 uint32

func (ip IP4) next() IP4 {
	return ip + 1
}

func (ip IP4) prev() IP4 {
	return ip - 1
}

func (ip IP4) nextReversed(mask byte) IP4 {
	return ip + 1<<mask
}

func (ip IP4) prevReversed(mask byte) IP4 {
	return ip - 1<<mask
}

func (ip IP4) ToNative() net.IP {
	return net.IP{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}
}

func (ip IP4) String() string {
	return ip.ToNative().String()
}

func NewIP4(s string) IP4 {
	// I'm lazy
	ipArr := net.ParseIP(s).To4()
	ip := IP4(binary.BigEndian.Uint32(ipArr))
	return ip
}

const (
	IP4MAX = ^IP4(0)
	IP4MIN = IP4(0)
)
