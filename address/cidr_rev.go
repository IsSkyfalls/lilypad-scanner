package address

import (
	"fmt"
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
	cidr       CIDR4Reversed
	counter    uint32
	skipNormal []CIDR4
}

func (cidr CIDR4Reversed) Iterator() *CIDR4RevIterator {
	return &CIDR4RevIterator{
		cidr: cidr,
	}
}

func (iter *CIDR4RevIterator) Resume(counter uint32) *CIDR4RevIterator {
	atomic.StoreUint32(&iter.counter, counter)
	return iter
}

func (iter *CIDR4RevIterator) RegisterSkip(cidr CIDR4) *CIDR4RevIterator {
	cpy := iter.skipNormal
	for i, e := range cpy {
		if e.low > cidr.low {
			cpy = append(cpy[i:], cpy[:i+1]...)
			cpy[i] = cidr
			iter.skipNormal = cpy
			return iter
		}
	}
	iter.skipNormal = append(iter.skipNormal, cidr)
	return iter
}

func (iter *CIDR4RevIterator) Next() (IP4, bool) {
	// actually this is getThenIncrement, so we can cover 0 to max
	for {
		this := atomic.LoadUint32(&iter.counter)
		next := this + 1
		if next > iter.cidr.count || next < this {
			return 0, false
		}
		ip := iter.cidr.GetNthAddr(this)
		// skip
		for {
			if skipCount, needed := iter.calcSkip(ip); needed {
				fmt.Println("skip addresses " + fmt.Sprint(skipCount))
				next += skipCount
				ip = iter.cidr.GetNthAddr(next)
				fmt.Println("next: " + ip.String())
			}
			break
		}
		if atomic.CompareAndSwapUint32(&iter.counter, this, next) {
			return ip, true
		}
	}
}

func (iter *CIDR4RevIterator) calcSkip(addr IP4) (uint32, bool) {
	for _, cidr := range iter.skipNormal {
		if cidr.Contains(addr) {
			if iter.cidr.prefix+cidr.prefix > 32 {
				return 1, true
			} else {
				skip := 1 << (32 - cidr.prefix - iter.cidr.prefix)
				return uint32(skip), true
			}
		}
	}
	return 0, false
}

func (iter *CIDR4RevIterator) Current() IP4 {
	c := atomic.LoadUint32(&iter.counter)
	if c > 0 {
		c--
	}
	return iter.cidr.GetNthAddr(c)
}
