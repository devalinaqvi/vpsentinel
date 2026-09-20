package ports

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type socket struct {
	Proto string
	IP    net.IP
	Port  int
	Inode string
}

func parseHexPort(s string) (int, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	return int(v), err
}

func hexToIPv4(s string) (net.IP, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return nil, fmt.Errorf("bad ipv4 hex %q", s)
	}
	return net.IPv4(b[3], b[2], b[1], b[0]), nil
}

func hexToIPv6(s string) (net.IP, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("bad ipv6 hex %q", s)
	}
	ip := make(net.IP, 16)
	for w := range 4 {
		ip[w*4+0] = b[w*4+3]
		ip[w*4+1] = b[w*4+2]
		ip[w*4+2] = b[w*4+1]
		ip[w*4+3] = b[w*4+0]
	}
	return ip, nil
}

func parseProcNet(proto string, data []byte) ([]socket, error) {
	var out []socket
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		local, state, inode := f[1], f[3], f[9]
		isTCP := strings.HasPrefix(proto, "tcp")
		if isTCP && state != "0A" {
			continue
		}
		if !isTCP && state != "07" {
			continue
		}
		hasPort := strings.SplitN(local, ":", 2)
		if len(hasPort) != 2 {
			continue
		}
		var ip net.IP
		var err error
		if strings.Contains(proto, "6") {
			ip, err = hexToIPv6(hasPort[0])
		} else {
			ip, err = hexToIPv4(hasPort[0])
		}
		if err != nil {
			continue
		}
		port, err := parseHexPort(hasPort[1])
		if err != nil {
			continue
		}
		out = append(out, socket{Proto: proto, IP: ip, Port: port, Inode: inode})
	}
	return out, nil
}
