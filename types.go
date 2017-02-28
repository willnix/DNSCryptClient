package main

// SignedBincertFields Represents the detailed structure of a DNSC certificate
type SignedBincertFields struct {
	ServerPublicKey [32]byte
	MagicQuery      [8]byte
	Serial          [4]byte
	TSBegin         uint32
	TSEnd           uint32
}

// SignedBincert Represents the structure of a DNSC certificate as needed to verify the signature
type SignedBincert struct {
	MagicCert    [4]byte
	VersionMajor uint16
	VersionMinor uint16

	Signature [64]byte

	SignedData [52]byte
}

// DNSCryptQueryHeader represents the header of a DNSC encrypted query
type DNSCryptQueryHeader struct {
	ClientMagic     [8]byte
	ClientPublicKey [32]byte
	ClientNonce     [12]byte
}

// DNSCryptQueryHeader represents the header of a DNSC encrypted reply
type DNSCryptResponseHeader struct {
	ServerMagic [8]byte
	ClientNonce [12]byte
	ServerNonce [12]byte
}
