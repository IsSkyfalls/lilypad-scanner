package address

import (
	"sync/atomic"
)

type CIDR4Reversed CIDR4

func (cidr CIDR4Reversed) Contains(ip IP4) bool {
	return (ip^cidr.ip)&^(IP4MAX<<cidr.prefix) == 0
}

func (cidr CIDR4Reversed) GetNthAddr(n uint32) IP4 {
	return cidr.low | IP4(n)<<uint32(cidr.prefix)
}

func NewCIDR4Reversed(s string) CIDR4Reversed {
	ip, prefix := parseCIDR(s, "|")
	return CIDR4Reversed{
		ip:     ip,
		prefix: prefix,
		low:    ip & ^(IP4MAX << prefix),
		high:   ip | IP4MAX<<prefix,
		count:  1 << (32 - prefix),
	}
}

type CIDR4RevIterator struct {
	cidr    CIDR4Reversed
	counter uint32
}

func (cidr CIDR4Reversed) Iterator() CIDR4RevIterator {
	return CIDR4RevIterator{
		cidr: cidr,
	}
}

func (iter *CIDR4RevIterator) Resume(counter uint32) *CIDR4RevIterator {
	atomic.StoreUint32(&iter.counter, counter)
	return iter
}

func (iter *CIDR4RevIterator) Next() (IP4, bool) {
	// actually this is getThenIncrement, so we can cover 0 to max
	for {
		this := atomic.LoadUint32(&iter.counter)
		next := this + 1
		if next > iter.cidr.count || next == 0 {
			return 0, false
		}
		if atomic.CompareAndSwapUint32(&iter.counter, this, next) {
			return iter.cidr.GetNthAddr(this), true
		}
	}
}

func (iter *CIDR4RevIterator) Current() IP4 {
	c := atomic.LoadUint32(&iter.counter)
	if c > 0 {
		c--
	}
	return iter.cidr.GetNthAddr(c)
}
