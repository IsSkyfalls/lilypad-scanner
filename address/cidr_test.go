package address

import (
	"github.com/stretchr/testify/assert"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCIDR4(t *testing.T) {
	assert.Equal(t, NewIP4("192.168.2.0").ToNative(), net.ParseIP("192.168.2.0").To4())
	assert.Equal(t, NewIP4("192.168.2.0"), NewCIDR4("192.168.2.0/24").low)
	assert.Equal(t, NewIP4("192.168.2.255"), NewCIDR4("192.168.2.0/24").high)

	assert.True(t, NewCIDR4("192.168.2.0/24").Contains(NewIP4("192.168.2.255")))
	assert.False(t, NewCIDR4("192.168.2.0/24").Contains(NewIP4("192.168.3.255")))
}

func TestCIDR4Reversed(t *testing.T) {
	assert.Equal(t, NewIP4("0.0.0.123"), NewCIDR4Reversed("0.0.0.123|8").low)
	assert.Equal(t, NewIP4("255.255.255.123"), NewCIDR4Reversed("0.0.0.123|8").high)

	assert.True(t, NewCIDR4Reversed("0.0.0.123|8").Contains(NewIP4("1.1.1.123")))
	assert.False(t, NewCIDR4Reversed("0.0.0.123|8").Contains(NewIP4("1.1.1.255")))
}

func TestCIDR4Reversed_Iterator(t *testing.T) {
	iter := NewCIDR4Reversed("0.0.1.123|20").Iterator()
	start := NewIP4("0.0.1.123")
	for i := 0; i < 256*2; i++ {
		next, ok := iter.Next()
		assert.True(t, ok)
		assert.Equal(t, start, next)
		start = start.nextReversed(iter.cidr.prefix)
	}

	block := make(chan bool)
	wg := sync.WaitGroup{}
	count := uint64(0)
	for i := 0; i < 5000; i++ {
		go func() {
			wg.Add(1)
			<-block
			for {
				next, ok := iter.Next()
				if !ok {
					wg.Done()
					return
				}
				if !iter.cidr.Contains(next) {
					assert.Fail(t, "Invalid address: "+next.String())
				}
				atomic.AddUint64(&count, 1)
			}
		}()
	}
	close(block)
	wg.Wait()
	assert.Equal(t, uint64(iter.cidr.count-256*2), count)
	assert.Equal(t, NewIP4("0.0.1.123")|IP4MAX<<iter.cidr.prefix, iter.Current())
}
