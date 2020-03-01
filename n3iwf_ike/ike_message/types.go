package ike_message

// IKE types
type IKEType uint8

const (
	NoNext = 0
	TypeSA = iota + 32
	TypeKE
	TypeIDi
	TypeIDr
	TypeCERT
	TypeCERTreq
	TypeAUTH
	TypeNiNr
	TypeN
	TypeD
	TypeV
	TypeTSi
	TypeTSr
	TypeSK
	TypeCP
	TypeEAP
)

// EAP types
type EAPType uint8

const (
	EAPTypeIdentity = iota + 1
	EAPTypeNotification
	EAPTypeNak
	EAPTypeExpanded = 254
)

// used for SecurityAssociation-Proposal-Transform TransformType
const (
	TypeEncryptionAlgorithm = iota + 1
	TypePseudorandomFunction
	TypeIntegrityAlgorithm
	TypeDiffieHellmanGroup
	TypeExtendedSequenceNumbers
)

// used for TrafficSelector-Individual Traffic Selector TSType
const (
	TS_IPV4_ADDR_RANGE = 7
	TS_IPV6_ADDR_RANGE = 8
)
