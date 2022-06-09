package address

import (
	"github.com/stretchr/testify/assert"
	"net"
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
