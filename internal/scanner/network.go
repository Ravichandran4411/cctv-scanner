package scanner

import (
	"fmt"
	"net"
)

// NetworkInterface represents a network interface with its details
type NetworkInterface struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	CIDR string `json:"cidr"`
}

// DetectNetworkInterfaces detects available network interfaces
func DetectNetworkInterfaces() []NetworkInterface {
	var result []NetworkInterface

	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			var network *net.IPNet

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				network = v
			case *net.IPAddr:
				ip = v.IP
			}

			// Only IPv4 addresses
			if ip == nil || ip.To4() == nil {
				continue
			}

			// Calculate network CIDR
			if network != nil {
				networkIP := ip.Mask(network.Mask)
				ones, _ := network.Mask.Size()
				cidr := fmt.Sprintf("%s/%d", networkIP.String(), ones)

				result = append(result, NetworkInterface{
					Name: iface.Name,
					IP:   ip.String(),
					CIDR: cidr,
				})
			}
		}
	}

	return result
}
