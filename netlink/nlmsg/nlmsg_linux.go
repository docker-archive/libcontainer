/*
Package nlmsg provides a low level interface to netlink messages.

It provides sockets and message handling for generic netlink
communication.  It does not provide wrapping functions for any
specific message types.

The system netlink message structures are wrapped to provide a
representation that is easier to manipulate.
*/

package nlmsg

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// Sequence counter for netlink messages so replies can be matched with requests.
var nextSeqNr uint32

// Native byte order conversions.  This is initialized to the
// platforms native byte order.
var Native binary.ByteOrder

func init() {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		Native = binary.BigEndian
	} else {
		Native = binary.LittleEndian
	}
}

// GetIpFamily returns the socket address family for the given net.IP instance.
func GetIpFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return syscall.AF_INET
	}
	if ip.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

// NetlinkRequestData is a type wrapper for system specified struts.
// Use this to provide an alternative representation of a struct that is more
// amenable to manipluation by the user of this package.
type NetlinkRequestData interface {
	Len() int
	ToWireFormat() []byte
}

type IfInfomsg struct {
	syscall.IfInfomsg
}

// NewIfInfomsg returns a new IfInfomsg for the specified socket family (AF_*).
func NewIfInfomsg(family int) *IfInfomsg {
	return &IfInfomsg{
		IfInfomsg: syscall.IfInfomsg{
			Family: uint8(family),
		},
	}
}

// NewIfInfomsgChild returns a new IfInfomsg which has been appended to the parent RtAttr sequence.
func NewIfInfomsgChild(parent *RtAttr, family int) *IfInfomsg {
	msg := NewIfInfomsg(family)
	parent.children = append(parent.children, msg)
	return msg
}

// ToWireFormat returns a wire format representation of the IfInfomsg.
func (msg *IfInfomsg) ToWireFormat() []byte {
	length := syscall.SizeofIfInfomsg
	b := make([]byte, length)
	b[0] = msg.Family
	b[1] = 0
	Native.PutUint16(b[2:4], msg.Type)
	Native.PutUint32(b[4:8], uint32(msg.Index))
	Native.PutUint32(b[8:12], msg.Flags)
	Native.PutUint32(b[12:16], msg.Change)
	return b
}

// Len returns the length in bytes of an IfInfomsg.
func (msg *IfInfomsg) Len() int {
	return syscall.SizeofIfInfomsg
}

type IfAddrmsg struct {
	syscall.IfAddrmsg
}

// NewIfAddrmsg returns a new IfAddrmsg for the specified socket family (AF_*).
func NewIfAddrmsg(family int) *IfAddrmsg {
	return &IfAddrmsg{
		IfAddrmsg: syscall.IfAddrmsg{
			Family: uint8(family),
		},
	}
}

// ToWireFormat returns a wire format representation of the IfAddrmsg.
func (msg *IfAddrmsg) ToWireFormat() []byte {
	length := syscall.SizeofIfAddrmsg
	b := make([]byte, length)
	b[0] = msg.Family
	b[1] = msg.Prefixlen
	b[2] = msg.Flags
	b[3] = msg.Scope
	Native.PutUint32(b[4:8], msg.Index)
	return b
}

// Len returns the length in bytes of an IfInfomsg.
func (msg *IfAddrmsg) Len() int {
	return syscall.SizeofIfAddrmsg
}

type RtMsg struct {
	syscall.RtMsg
}

// NewRtMsg returns a new RtMsg
func NewRtMsg() *RtMsg {
	return &RtMsg{
		RtMsg: syscall.RtMsg{
			Table:    syscall.RT_TABLE_MAIN,
			Scope:    syscall.RT_SCOPE_UNIVERSE,
			Protocol: syscall.RTPROT_BOOT,
			Type:     syscall.RTN_UNICAST,
		},
	}
}

// ToWireFormat returns a wire format representation of the RtMsg.
func (msg *RtMsg) ToWireFormat() []byte {
	length := syscall.SizeofRtMsg
	b := make([]byte, length)
	b[0] = msg.Family
	b[1] = msg.Dst_len
	b[2] = msg.Src_len
	b[3] = msg.Tos
	b[4] = msg.Table
	b[5] = msg.Protocol
	b[6] = msg.Scope
	b[7] = msg.Type
	Native.PutUint32(b[8:12], msg.Flags)
	return b
}

// Len returns the length in bytes of RtMsg
func (msg *RtMsg) Len() int {
	return syscall.SizeofRtMsg
}

// Align the given length to boundary specified by the RTA_ALIGNTO constant.
func RtaAlignOf(attrlen int) int {
	return (attrlen + syscall.RTA_ALIGNTO - 1) & ^(syscall.RTA_ALIGNTO - 1)
}

type RtAttr struct {
	syscall.RtAttr
	Data     []byte
	children []NetlinkRequestData
}

// NewRtAttr returns a new RtAttr with the specified type, data and no child attributes.
func NewRtAttr(attrType int, data []byte) *RtAttr {
	return &RtAttr{
		RtAttr: syscall.RtAttr{
			Type: uint16(attrType),
		},
		children: []NetlinkRequestData{},
		Data:     data,
	}
}

// NewRtAttrChild adds a child attribute with the given type and data to a RtAttr.
func NewRtAttrChild(parent *RtAttr, attrType int, data []byte) *RtAttr {
	attr := NewRtAttr(attrType, data)
	parent.children = append(parent.children, attr)
	return attr
}

// Len returns the length in bytes of a RtAttr.
func (a *RtAttr) Len() int {
	if len(a.children) == 0 {
		return (syscall.SizeofRtAttr + len(a.Data))
	}

	l := 0
	for _, child := range a.children {
		l += child.Len()
	}
	l += syscall.SizeofRtAttr
	return RtaAlignOf(l + len(a.Data))
}

// ToWireFormat returns a wire format representation of the RtAttr.
func (a *RtAttr) ToWireFormat() []byte {
	length := a.Len()
	buf := make([]byte, RtaAlignOf(length))

	if a.Data != nil {
		copy(buf[4:], a.Data)
	} else {
		next := 4
		for _, child := range a.children {
			childBuf := child.ToWireFormat()
			copy(buf[next:], childBuf)
			next += RtaAlignOf(len(childBuf))
		}
	}

	if l := uint16(length); l != 0 {
		Native.PutUint16(buf[0:2], l)
	}
	Native.PutUint16(buf[2:4], a.Type)
	return buf
}

// Uint32Attr returns a new RtAttr with the specified attribute type and uint32 value.
func Uint32Attr(t int, n uint32) *RtAttr {
	buf := make([]byte, 4)
	Native.PutUint32(buf, n)
	return NewRtAttr(t, buf)
}

type NetlinkRequest struct {
	syscall.NlMsghdr
	Data []NetlinkRequestData
}

// ToWireFormat returns a wire format representation of the NetlinkRequest.
func (rr *NetlinkRequest) ToWireFormat() []byte {
	length := rr.Len
	dataBytes := make([][]byte, len(rr.Data))
	for i, data := range rr.Data {
		dataBytes[i] = data.ToWireFormat()
		length += uint32(len(dataBytes[i]))
	}
	b := make([]byte, length)
	Native.PutUint32(b[0:4], length)
	Native.PutUint16(b[4:6], rr.Type)
	Native.PutUint16(b[6:8], rr.Flags)
	Native.PutUint32(b[8:12], rr.Seq)
	Native.PutUint32(b[12:16], rr.Pid)

	next := 16
	for _, data := range dataBytes {
		copy(b[next:], data)
		next += len(data)
	}
	return b
}

// AddData adds a NetlinkRequestData instance to the NetlinkRequest.
func (rr *NetlinkRequest) AddData(data NetlinkRequestData) {
	if data != nil {
		rr.Data = append(rr.Data, data)
	}
}

// NewNetlinkRequest returns a new NetlinkRequest with the specified protocol and flags.
func NewNetlinkRequest(proto, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: syscall.NlMsghdr{
			Len:   uint32(syscall.NLMSG_HDRLEN),
			Type:  uint16(proto),
			Flags: syscall.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
		},
	}
}

type NetlinkSocket struct {
	fd  int
	lsa syscall.SockaddrNetlink
}

// NewNetlinkSocket returns a new NetlinkSocket.
func NewNetlinkSocket() (*NetlinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd: fd,
	}
	s.lsa.Family = syscall.AF_NETLINK
	if err := syscall.Bind(fd, &s.lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return s, nil
}

// Close closes the netlink socket.
func (s *NetlinkSocket) Close() {
	syscall.Close(s.fd)
}

// Send sends the NetlinkRequest via the socket.
func (s *NetlinkSocket) Send(request *NetlinkRequest) error {
	if err := syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}

// Receive returns a slice of NetlinkMessage messages received from the netlink socket.
func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, error) {
	rb := make([]byte, syscall.Getpagesize())
	nr, _, err := syscall.Recvfrom(s.fd, rb, 0)
	if err != nil {
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, ErrShortResponse
	}
	rb = rb[:nr]
	return syscall.ParseNetlinkMessage(rb)
}

// GetPid returns the PID associated with the netlink socket.
func (s *NetlinkSocket) GetPid() (uint32, error) {
	lsa, err := syscall.Getsockname(s.fd)
	if err != nil {
		return 0, err
	}
	switch v := lsa.(type) {
	case *syscall.SockaddrNetlink:
		return v.Pid, nil
	}
	return 0, ErrWrongSockType
}

// CheckMessage checks that the NetlinkMessage matches the specified
// message sequence number and PID.  Returns io.EOF id the message
// type is NLMSG_DONE. Returns an Errno id the message type is
// NLMSG_ERROR.
func (s *NetlinkSocket) CheckMessage(m syscall.NetlinkMessage, seq, pid uint32) error {
	if m.Header.Seq != seq {
		return fmt.Errorf("netlink: invalid seq %d, expected %d", m.Header.Seq, seq)
	}
	if m.Header.Pid != pid {
		return fmt.Errorf("netlink: wrong pid %d, expected %d", m.Header.Pid, pid)
	}
	if m.Header.Type == syscall.NLMSG_DONE {
		return io.EOF
	}
	if m.Header.Type == syscall.NLMSG_ERROR {
		e := int32(Native.Uint32(m.Data[0:4]))
		if e == 0 {
			return io.EOF
		}
		return syscall.Errno(-e)
	}
	return nil
}

// HandleAck reads a message acknowledgement from the netlink socket.
// Returns an error if the message failes to match the specified
// sequence.  The message is discarded.
func (s *NetlinkSocket) HandleAck(seq uint32) error {
	pid, err := s.GetPid()
	if err != nil {
		return err
	}

outer:
	for {
		msgs, err := s.Receive()
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if err := s.CheckMessage(m, seq, pid); err != nil {
				if err == io.EOF {
					break outer
				}
				return err
			}
		}
	}

	return nil
}

// ZeroTerminated returns a byte slice with a zero terminated byte slice of the given string.
func ZeroTerminated(s string) []byte {
	return []byte(s + "\000")
}

// NonZeroTerminated returns a byte slice with a byte slice of the given string.
func NonZeroTerminated(s string) []byte {
	return []byte(s)
}
