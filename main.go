package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/willnix/dnscrypt"
)
import "os"

var (
	providerKey   = []byte{0xB7, 0x35, 0x11, 0x40, 0x20, 0x6F, 0x22, 0x5D, 0x3E, 0x2B, 0xD8, 0x22, 0xD7, 0xFD, 0x69, 0x1E, 0xA1, 0xC3, 0x3C, 0xC8, 0xD6, 0x66, 0x8D, 0x0C, 0xBE, 0x04, 0xBF, 0xAB, 0xCA, 0x43, 0xFB, 0x79}
	providerName  = "2.dnscrypt-cert.opendns.com"
	serverAddress = "208.67.220.220:443"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please specify domain to look up!")
		return
	}

	// get the servers certificate
	bincertFields, err := dnscrypt.GetValidCert(serverAddress, providerName, providerKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	// build A query
	var msg dns.Msg
	msg.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeA)

	// send the query
	response, err := dnscrypt.ExchangeEncrypted(serverAddress, msg, bincertFields)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(response.Answer) == 0 {
		fmt.Println("No answer section DNS in response!")
		return
	}

	// Look for an A record. We ignore CNAMEs for now.
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			fmt.Println(a.A.String())
		}
	}

	return
}
