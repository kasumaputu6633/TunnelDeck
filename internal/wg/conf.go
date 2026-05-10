package wg

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ConfFile models the fields of /etc/wireguard/wg0.conf we read.
// Unknown keys are preserved in rawLines on write.
type ConfFile struct {
	Address    []string
	ListenPort int
	PrivateKey string
	MTU        int
	PostUp     []string
	PostDown   []string

	Peers []ConfPeer

	rawLines []string
}

type ConfPeer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int

	// Comment carries the "# tunneldeck:node=<name>" marker we use to
	// correlate file peers with DB rows.
	Comment string
}

// ReadConfFile parses path. Missing file returns (nil, os.ErrNotExist).
func ReadConfFile(path string) (*ConfFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseConf(f)
}

func ParseConf(r io.Reader) (*ConfFile, error) {
	c := &ConfFile{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	section := ""
	var currentPeer *ConfPeer

	for sc.Scan() {
		raw := sc.Text()
		c.rawLines = append(c.rawLines, raw)

		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if section == "Peer" && currentPeer != nil {
				c.Peers = append(c.Peers, *currentPeer)
				currentPeer = nil
			}
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if section == "Peer" {
				currentPeer = &ConfPeer{}
			}
			continue
		}

		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])

		switch section {
		case "Interface":
			switch strings.ToLower(key) {
			case "address":
				for _, a := range strings.Split(val, ",") {
					c.Address = append(c.Address, strings.TrimSpace(a))
				}
			case "listenport":
				c.ListenPort, _ = strconv.Atoi(val)
			case "privatekey":
				c.PrivateKey = val
			case "mtu":
				c.MTU, _ = strconv.Atoi(val)
			case "postup":
				c.PostUp = append(c.PostUp, val)
			case "postdown":
				c.PostDown = append(c.PostDown, val)
			}
		case "Peer":
			if currentPeer == nil {
				continue
			}
			switch strings.ToLower(key) {
			case "publickey":
				currentPeer.PublicKey = val
			case "presharedkey":
				currentPeer.PresharedKey = val
			case "allowedips":
				for _, a := range strings.Split(val, ",") {
					currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, strings.TrimSpace(a))
				}
			case "endpoint":
				currentPeer.Endpoint = val
			case "persistentkeepalive":
				currentPeer.PersistentKeepalive, _ = strconv.Atoi(val)
			}
		}
	}
	if section == "Peer" && currentPeer != nil {
		c.Peers = append(c.Peers, *currentPeer)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// RenderNodeConfig builds the node-side wg0.conf body. The node generates its
// own private key locally; nodePrivateKeyPlaceholder is the string the user
// replaces before activating the config.
func RenderNodeConfig(nodeWGIP, nodePrivateKeyPlaceholder, gatewayPublicKey, gatewayEndpoint, gatewayAllowedIPs string, keepalive, mtu int) string {
	if keepalive <= 0 {
		keepalive = 25
	}
	if mtu <= 0 {
		mtu = 1380
	}
	var b strings.Builder
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "Address = %s\n", nodeWGIP)
	fmt.Fprintf(&b, "PrivateKey = %s\n", nodePrivateKeyPlaceholder)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "[Peer]")
	fmt.Fprintf(&b, "PublicKey = %s\n", gatewayPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", gatewayEndpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", gatewayAllowedIPs)
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)
	return b.String()
}
