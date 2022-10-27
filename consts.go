package did

var VRType = map[int]string{
	0: "authentication",
	1: "assertionMethod",
	2: "keyAgreement",
	3: "capabilityInvocation",
	4: "capabilityDelegation",
}

const (
	SEPARATOR    = ":"
	MethodPrefix = "did" + SEPARATOR + "metablox" + SEPARATOR
)
