package main

import "fmt"
import "os"

var (
	providerKey   = []byte{0xB7, 0x35, 0x11, 0x40, 0x20, 0x6F, 0x22, 0x5D, 0x3E, 0x2B, 0xD8, 0x22, 0xD7, 0xFD, 0x69, 0x1E, 0xA1, 0xC3, 0x3C, 0xC8, 0xD6, 0x66, 0x8D, 0x0C, 0xBE, 0x04, 0xBF, 0xAB, 0xCA, 0x43, 0xFB, 0x79}
	providerName  = "2.dnscrypt-cert.opendns.com"
	serverAddress = "208.67.220.220:443"
	dnsMaxSizeUDP = 65536 - 20 - 8
)

func main() {
	bincertFields, err := GetValidCert(serverAddress, providerName, providerKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	ip, err := ExchangeEncryptedAQuery(os.Args[1], bincertFields)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(ip)
}
