/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpfkit

import (
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// MustEncodeDNS returns the DNS packet representation of a domain name or panic
func MustEncodeDNS(name string) [DNSMaxLength]byte {
	b, err := EncodeDNS(name)
	if err != nil {
		logrus.Fatal(err)
	}
	return b
}

// EncodeDNS returns the DNS packet representation of a domain name
func EncodeDNS(name string) ([DNSMaxLength]byte, error) {
	buf := [DNSMaxLength]byte{}
	if len(name)+1 > DNSMaxLength {
		return buf, errors.New("DNS name too long")
	}
	i := 0
	for _, label := range strings.Split(name, ".") {
		sublen := len(label)
		if sublen > DNSMaxLabelLength {
			return buf, errors.New("DNS label too long")
		}
		buf[i] = byte(sublen)
		copy(buf[i+1:], label)
		i = i + sublen + 1
	}
	return buf, nil
}

// MustEncodeIPv4 returns an IPv4 in its 4 bytes long representation or fatal
func MustEncodeIPv4(ip string) []byte {
	buf, err := EncodeIPv4(ip)
	if err != nil {
		logrus.Fatal(err)
	}
	return buf
}

// EncodeIPv4 returns an IPv4 in its 4 byte long representation
func EncodeIPv4(ip string) ([]byte, error) {
	rawIP := net.ParseIP(ip)
	if len(rawIP) == 0 {
		return nil, errors.Errorf("invalid IP: %s", ip)
	}
	rawIP = rawIP.To4()
	if len(rawIP) == 0 {
		return nil, errors.Errorf("invalid IPv4: %s", ip)
	}
	//var buf bytes.Buffer
	//for i := len(rawIP) - 1; i >= 0; i-- {
	//	buf.WriteByte(rawIP[i])
	//}
	return rawIP, nil
}
