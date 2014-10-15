package nlmsg

import (
	"testing"
)

func TestRtAttrToWireFormat(t *testing.T) {
	if testing.Short() {
		return
	}

	for i := 1; i <= 32; i++ {
		rtattr := NewRtAttr(1, make([]byte, i))
		if len(rtattr.ToWireFormat()) != rtattr.Len() {
			t.Errorf("Invalid wire length for RtAttr with length %v", i)
		}
	}
}
