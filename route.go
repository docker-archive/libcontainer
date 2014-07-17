package libcontainer

// Routes can be specified to create entries in the route table as the container is started
//
// All of destination, source, and gateway should be either IPv4 or IPv6.
// One of the three options must be present, and ommitted entries will use their
// IP family default for the route table.  For IPv4 for example, setting the
// gateway to 1.2.3.4 and the interface to eth0 will set up a standard
// destination of 0.0.0.0(or *) when viewed in the route table.
type Route struct {
	// Sets the destination and mask, should be a CIDR.  Accepts IPv4 and IPv6
	Destination string `json:"destination,omitempty"`

	// Sets the source and mask, should be a CIDR.  Accepts IPv4 and IPv6
	Source string `json:"source,omitempty"`

	// Sets the gateway.  Accepts IPv4 and IPv6
	Gateway string `json:"gateway,omitempty"`

	// The device to set this route up for, for example: eth0
	InterfaceName string `json:"interface_name,omitempty"`
}
