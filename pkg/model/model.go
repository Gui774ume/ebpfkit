package model

// FlowType is used to qualify the type of a flow
type FlowType uint32

const (
	// IngressFlow is a TCP or UDP ingress flow
	IngressFlow FlowType = iota + 1
	// EgressFlow is a TCP or UDP egress flow
	EgressFlow
	// ARPRequest is used for ARP requests
	ARPRequest
	// ARPReply is used for ARP replies
	ARPReply
	// Syn is used for TCP SYN packets
	Syn
	// Ack is used for TCP Ack packets
	Ack
	// Reset is used for TCP Reset packets
	Reset
)
