// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

const preferPublicIP bool = true

var (
	// addrsMu protects addrs. Outside the addresses struct
	// so that we can Uninitialize() without linter complaining
	// about lock copying.
	addrsMu lock.RWMutex
	addrs   addresses
)

type addresses struct {
	ipv4Loopback      net.IP
	ipv4Address       net.IP
	ipv4RouterAddress net.IP
	ipv4NodePortAddrs map[string]net.IP // iface name => ip addr
	ipv4MasqAddrs     map[string]net.IP // iface name => ip addr
	ipv6Address       net.IP
	ipv6RouterAddress net.IP
	ipv6NodePortAddrs map[string]net.IP // iface name => ip addr
	ipv6MasqAddrs     map[string]net.IP // iface name => ip addr
	ipv4AllocRange    *cidr.CIDR
	ipv6AllocRange    *cidr.CIDR
	routerInfo        RouterInfo

	// k8s Node External IP
	ipv4ExternalAddress net.IP
	ipv6ExternalAddress net.IP

	// Addresses of the cilium-health endpoint located on the node
	ipv4HealthIP net.IP
	ipv6HealthIP net.IP

	// k8s Node IP (either InternalIP or ExternalIP or nil; the former is preferred)
	k8sNodeIP net.IP

	ipsecKeyIdentity uint8

	wireguardPubKey string
}

type RouterInfo interface {
	GetIPv4CIDRs() []net.IPNet
	GetMac() mac.MAC
	GetInterfaceNumber() int
}

func makeIPv6HostIP() net.IP {
	ipstr := "fc00::10CA:1"
	ip := net.ParseIP(ipstr)
	if ip == nil {
		log.WithField(logfields.IPAddr, ipstr).Fatal("Unable to parse IP")
	}

	return ip
}

// InitDefaultPrefix initializes the node address and allocation prefixes with
// default values derived from the system. device can be set to the primary
// network device of the system in which case the first address with global
// scope will be regarded as the system's node address.
func InitDefaultPrefix(device string) {
	addrsMu.Lock()
	defer addrsMu.Unlock()

	if option.Config.EnableIPv4 {
		ip, err := firstGlobalV4Addr(device, addrs.ipv4RouterAddress, preferPublicIP)
		if err != nil {
			return
		}

		if addrs.ipv4Address == nil {
			addrs.ipv4Address = ip
		}

		if addrs.ipv4AllocRange == nil {
			// If the IPv6AllocRange is not nil then the IPv4 allocation should be
			// derived from the IPv6AllocRange.
			//                     vvvv vvvv
			// FD00:0000:0000:0000:0000:0000:0000:0000
			if addrs.ipv6AllocRange != nil {
				ip = net.IPv4(addrs.ipv6AllocRange.IP[8],
					addrs.ipv6AllocRange.IP[9],
					addrs.ipv6AllocRange.IP[10],
					addrs.ipv6AllocRange.IP[11])
			}
			v4range := fmt.Sprintf(defaults.DefaultIPv4Prefix+"/%d",
				ip.To4()[3], defaults.DefaultIPv4PrefixLen)
			_, ip4net, err := net.ParseCIDR(v4range)
			if err != nil {
				log.WithError(err).WithField(logfields.V4Prefix, v4range).Panic("BUG: Invalid default IPv4 prefix")
			}

			addrs.ipv4AllocRange = cidr.NewCIDR(ip4net)
			log.WithField(logfields.V4Prefix, addrs.ipv4AllocRange).Info("Using autogenerated IPv4 allocation range")
		}
	}

	if option.Config.EnableIPv6 {
		if addrs.ipv6Address == nil {
			// Find a IPv6 node address first
			addrs.ipv6Address, _ = firstGlobalV6Addr(device, addrs.ipv6RouterAddress, preferPublicIP)
			if addrs.ipv6Address == nil {
				addrs.ipv6Address = makeIPv6HostIP()
			}
		}

		if addrs.ipv6AllocRange == nil && addrs.ipv4AllocRange != nil {
			// The IPv6 allocation should be derived from the IPv4 allocation.
			ip := addrs.ipv4AllocRange.IP
			v6range := fmt.Sprintf("%s%02x%02x:%02x%02x:0:0/%d",
				option.Config.IPv6ClusterAllocCIDRBase, ip[0], ip[1], ip[2], ip[3], 96)

			_, ip6net, err := net.ParseCIDR(v6range)
			if err != nil {
				log.WithError(err).WithField(logfields.V6Prefix, v6range).Panic("BUG: Invalid default IPv6 prefix")
			}

			addrs.ipv6AllocRange = cidr.NewCIDR(ip6net)
			log.WithField(logfields.V6Prefix, addrs.ipv6AllocRange).Info("Using autogenerated IPv6 allocation range")
		}
	}
}

// InitNodePortAddrs initializes NodePort IPv{4,6} addrs for the given devices.
// If inheritIPAddrFromDevice is non-empty, then the IP addr for the devices
// will be derived from it.
func InitNodePortAddrs(devices []string, inheritIPAddrFromDevice string) error {
	addrsMu.Lock()
	defer addrsMu.Unlock()

	var inheritedIP net.IP
	var err error

	if option.Config.EnableIPv4 {
		if inheritIPAddrFromDevice != "" {
			inheritedIP, err = firstGlobalV4Addr(inheritIPAddrFromDevice, addrs.k8sNodeIP, !preferPublicIP)
			if err != nil {
				return fmt.Errorf("failed to determine IPv4 of %s for NodePort", inheritIPAddrFromDevice)
			}
		}
		addrs.ipv4NodePortAddrs = make(map[string]net.IP, len(devices))
		for _, device := range devices {
			if inheritIPAddrFromDevice != "" {
				addrs.ipv4NodePortAddrs[device] = inheritedIP
			} else {
				ip, err := firstGlobalV4Addr(device, addrs.k8sNodeIP, !preferPublicIP)
				if err != nil {
					return fmt.Errorf("failed to determine IPv4 of %s for NodePort", device)
				}
				addrs.ipv4NodePortAddrs[device] = ip
			}
		}
	}

	if option.Config.EnableIPv6 {
		if inheritIPAddrFromDevice != "" {
			inheritedIP, err = firstGlobalV6Addr(inheritIPAddrFromDevice, addrs.k8sNodeIP, !preferPublicIP)
			if err != nil {
				return fmt.Errorf("Failed to determine IPv6 of %s for NodePort", inheritIPAddrFromDevice)
			}
		}
		addrs.ipv6NodePortAddrs = make(map[string]net.IP, len(devices))
		for _, device := range devices {
			if inheritIPAddrFromDevice != "" {
				addrs.ipv6NodePortAddrs[device] = inheritedIP
			} else {
				ip, err := firstGlobalV6Addr(device, addrs.k8sNodeIP, !preferPublicIP)
				if err != nil {
					return fmt.Errorf("Failed to determine IPv6 of %s for NodePort", device)
				}
				addrs.ipv6NodePortAddrs[device] = ip
			}
		}
	}

	return nil
}

// InitBPFMasqueradeAddrs initializes BPF masquerade addrs for the given devices.
func InitBPFMasqueradeAddrs(devices []string) error {
	initMasqueradeAddrs := func(masqAddrs map[string]net.IP, family int, logfield string) error {
		if ifaceName := option.Config.DeriveMasqIPAddrFromDevice; ifaceName != "" {
			ip, err := firstGlobalAddr(ifaceName, nil, family, preferPublicIP)
			if err != nil {
				return fmt.Errorf("Failed to determine IPv4 of %s for BPF masq", ifaceName)
			}
			for _, device := range devices {
				masqAddrs[device] = ip
			}
			return nil
		}

		for _, device := range devices {
			ip, err := firstGlobalAddr(device, addrs.k8sNodeIP, family, preferPublicIP)
			if err != nil {
				return fmt.Errorf("Failed to determine IP of %s for BPF masq", device)
			}

			masqAddrs[device] = ip
			log.WithFields(logrus.Fields{
				logfield:         ip,
				logfields.Device: device,
			}).Info("Masquerading IP selected for device")
		}

		return nil
	}

	addrsMu.Lock()
	defer addrsMu.Unlock()

	if option.Config.EnableIPv4 {
		addrs.ipv4MasqAddrs = make(map[string]net.IP, len(devices))
		err := initMasqueradeAddrs(addrs.ipv4MasqAddrs, netlink.FAMILY_V4, logfields.IPv4)
		if err != nil {
			return err
		}
	}
	if option.Config.EnableIPv6 {
		addrs.ipv6MasqAddrs = make(map[string]net.IP, len(devices))
		return initMasqueradeAddrs(addrs.ipv6MasqAddrs, netlink.FAMILY_V6, logfields.IPv6)
	}

	return nil
}

// GetIPv4Loopback returns the loopback IPv4 address of this node.
func GetIPv4Loopback() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv4Loopback
}

// SetIPv4Loopback sets the loopback IPv4 address of this node.
func SetIPv4Loopback(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv4Loopback = ip
	addrsMu.Unlock()
}

// GetIPv4AllocRange returns the IPv4 allocation prefix of this node
func GetIPv4AllocRange() *cidr.CIDR {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv4AllocRange
}

// GetIPv6AllocRange returns the IPv6 allocation prefix of this node
func GetIPv6AllocRange() *cidr.CIDR {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv6AllocRange
}

// SetIPv4 sets the IPv4 node address. It must be reachable on the network.
// It is set based on the following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
func SetIPv4(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv4Address = ip
	addrsMu.Unlock()
}

// GetIPv4 returns one of the IPv4 node address available with the following
// priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type.
// It must be reachable on the network.
func GetIPv4() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv4Address
}

// SetInternalIPv4Router sets the cilium internal IPv4 node address, it is allocated from the node prefix.
// This must not be conflated with k8s internal IP as this IP address is only relevant within the
// Cilium-managed network (this means within the node for direct routing mode and on the overlay
// for tunnel mode).
func SetInternalIPv4Router(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv4RouterAddress = ip
	addrsMu.Unlock()
}

// GetInternalIPv4Router returns the cilium internal IPv4 node address. This must not be conflated with
// k8s internal IP as this IP address is only relevant within the Cilium-managed network (this means
// within the node for direct routing mode and on the overlay for tunnel mode).
func GetInternalIPv4Router() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv4RouterAddress
}

// SetK8sExternalIPv4 sets the external IPv4 node address. It must be a public IP that is routable
// on the network as well as the internet.
func SetK8sExternalIPv4(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv4ExternalAddress = ip
	addrsMu.Unlock()
}

// GetK8sExternalIPv4 returns the external IPv4 node address. It must be a public IP that is routable
// on the network as well as the internet. It can return nil if no External IPv4 address is assigned.
func GetK8sExternalIPv4() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv4ExternalAddress
}

// GetRouterInfo returns additional information for the router, the cilium_host interface.
func GetRouterInfo() RouterInfo {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.routerInfo
}

// SetRouterInfo sets additional information for the router, the cilium_host interface.
func SetRouterInfo(info RouterInfo) {
	addrsMu.Lock()
	addrs.routerInfo = info
	addrsMu.Unlock()
}

// GetHostMasqueradeIPv4 returns the IPv4 address to be used for masquerading
// any traffic that is being forwarded from the host into the Cilium cluster.
func GetHostMasqueradeIPv4() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv4RouterAddress
}

// SetIPv4AllocRange sets the IPv4 address pool to use when allocating
// addresses for local endpoints
func SetIPv4AllocRange(net *cidr.CIDR) {
	addrsMu.Lock()
	addrs.ipv4AllocRange = net
	addrsMu.Unlock()
}

// Uninitialize resets this package to the default state, for use in
// testsuite code.
func Uninitialize() {
	addrsMu.Lock()
	addrs = addresses{}
	addrsMu.Unlock()
}

// GetNodePortIPv4Addrs returns the node-port IPv4 address for NAT
func GetNodePortIPv4Addrs() []net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	addrs4 := make([]net.IP, 0, len(addrs.ipv4NodePortAddrs))
	for _, addr := range addrs.ipv4NodePortAddrs {
		addrs4 = append(addrs4, addr)
	}
	return addrs4
}

// GetNodePortIPv4AddrsWithDevices returns the map iface => NodePort IPv4.
func GetNodePortIPv4AddrsWithDevices() map[string]net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return copyStringToNetIPMap(addrs.ipv4NodePortAddrs)
}

// GetNodePortIPv6Addrs returns the node-port IPv6 address for NAT
func GetNodePortIPv6Addrs() []net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	addrs6 := make([]net.IP, 0, len(addrs.ipv6NodePortAddrs))
	for _, addr := range addrs.ipv6NodePortAddrs {
		addrs6 = append(addrs6, addr)
	}
	return addrs6
}

// GetNodePortIPv6AddrsWithDevices returns the map iface => NodePort IPv6.
func GetNodePortIPv6AddrsWithDevices() map[string]net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return copyStringToNetIPMap(addrs.ipv6NodePortAddrs)
}

// GetMasqIPv4AddrsWithDevices returns the map iface => BPF masquerade IPv4.
func GetMasqIPv4AddrsWithDevices() map[string]net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return copyStringToNetIPMap(addrs.ipv4MasqAddrs)
}

// GetMasqIPv6AddrsWithDevices returns the map iface => BPF masquerade IPv6.
func GetMasqIPv6AddrsWithDevices() map[string]net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return copyStringToNetIPMap(addrs.ipv6MasqAddrs)
}

// SetIPv6NodeRange sets the IPv6 address pool to be used on this node
func SetIPv6NodeRange(net *cidr.CIDR) {
	addrsMu.Lock()
	addrs.ipv6AllocRange = net
	addrsMu.Unlock()
}

// AutoComplete completes the parts of addressing that can be auto derived
func AutoComplete() error {
	if option.Config.EnableHostIPRestore {
		// At this point, only attempt to restore the `cilium_host` IPs from
		// the filesystem because we haven't fully synced with K8s yet.
		restoreCiliumHostIPsFromFS()
	}

	InitDefaultPrefix(option.Config.DirectRoutingDevice)

	if option.Config.EnableIPv6 && addrs.ipv6AllocRange == nil {
		return fmt.Errorf("IPv6 allocation CIDR is not configured. Please specificy --ipv6-range")
	}

	if option.Config.EnableIPv4 && addrs.ipv4AllocRange == nil {
		return fmt.Errorf("IPv4 allocation CIDR is not configured. Please specificy --ipv4-range")
	}

	return nil
}

// RestoreHostIPs restores the router IPs (`cilium_host`) from a previous
// Cilium run. Router IPs from the filesystem are preferred over the IPs found
// in the Kubernetes resource (Node or CiliumNode), because we consider the
// filesystem to be the most up-to-date source of truth. The chosen router IP
// is then checked whether it is contained inside node CIDR (pod CIDR) range.
// If not, then the router IP is discarded and not restored.
//
// The restored IP is returned.
func RestoreHostIPs(ipv6 bool, fromK8s, fromFS net.IP, cidrs []*cidr.CIDR) net.IP {
	if !option.Config.EnableHostIPRestore {
		return nil
	}

	var (
		setter func(net.IP)
	)
	if ipv6 {
		setter = SetIPv6Router
	} else {
		setter = SetInternalIPv4Router
	}

	ip, err := chooseHostIPsToRestore(ipv6, fromK8s, fromFS, cidrs)
	switch {
	case err != nil && errors.Is(err, errDoesNotBelong):
		log.WithFields(logrus.Fields{
			logfields.CIDRS: cidrs,
		}).Infof(
			"The router IP (%s) considered for restoration does not belong in the Pod CIDR of the node. Discarding old router IP.",
			ip,
		)
		// Indicate that this IP will not be restored by setting to nil after
		// we've used it to log above.
		ip = nil
		setter(nil)
	case err != nil && errors.Is(err, errMismatch):
		log.Warnf(
			mismatchRouterIPsMsg,
			fromK8s, fromFS, option.LocalRouterIPv4, option.LocalRouterIPv6,
		)
		fallthrough // Above is just a warning; we still want to set the router IP regardless.
	case err == nil:
		setter(ip)
	}

	return ip
}

func chooseHostIPsToRestore(ipv6 bool, fromK8s, fromFS net.IP, cidrs []*cidr.CIDR) (ip net.IP, err error) {
	switch {
	// If both IPs are available, then check both for validity. We prefer the
	// local IP from the FS over the K8s IP.
	case fromK8s != nil && fromFS != nil:
		if fromK8s.Equal(fromFS) {
			ip = fromK8s
		} else {
			ip = fromFS
			err = errMismatch

			// Check if we need to fallback to using the fromK8s IP, in the
			// case that the IP from the FS is not within the CIDR. If we
			// fallback, then we also need to check the fromK8s IP is also
			// within the CIDR.
			for _, cidr := range cidrs {
				if cidr != nil && cidr.Contains(ip) {
					return
				} else if cidr != nil && cidr.Contains(fromK8s) {
					ip = fromK8s
					return
				}
			}
		}
	case fromK8s == nil && fromFS != nil:
		ip = fromFS
	case fromK8s != nil && fromFS == nil:
		ip = fromK8s
	case fromK8s == nil && fromFS == nil:
		// We do nothing in this case because there are no router IPs to
		// restore.
		return
	}

	for _, cidr := range cidrs {
		if cidr != nil && cidr.Contains(ip) {
			return
		}
	}

	err = errDoesNotBelong
	return
}

// restoreCiliumHostIPsFromFS restores the router IPs (`cilium_host`) from a
// previous Cilium run. The IPs are restored from the filesystem. This is part
// 1/2 of the restoration.
func restoreCiliumHostIPsFromFS() {
	// Read the previous cilium_host IPs from node_config.h for backward
	// compatibility.
	router4, router6 := getCiliumHostIPs()
	if option.Config.EnableIPv4 {
		SetInternalIPv4Router(router4)
	}
	if option.Config.EnableIPv6 {
		SetIPv6Router(router6)
	}
}

var (
	errMismatch      = errors.New("mismatched IPs")
	errDoesNotBelong = errors.New("IP does not belong to CIDR")
)

const mismatchRouterIPsMsg = "Mismatch of router IPs found during restoration. The Kubernetes resource contained %s, while the filesystem contained %s. Using the router IP from the filesystem. To change the router IP, specify --%s and/or --%s."

// ValidatePostInit validates the entire addressing setup and completes it as
// required
func ValidatePostInit() error {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	if option.Config.EnableIPv4 || option.Config.Tunnel != option.TunnelDisabled {
		if addrs.ipv4Address == nil {
			return fmt.Errorf("external IPv4 node address could not be derived, please configure via --ipv4-node")
		}
	}

	if option.Config.EnableIPv4 && addrs.ipv4RouterAddress == nil {
		return fmt.Errorf("BUG: Internal IPv4 node address was not configured")
	}

	return nil
}

// SetIPv6 sets the IPv6 address of the node
func SetIPv6(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv6Address = ip
	addrsMu.Unlock()
}

// GetIPv6 returns the IPv6 address of the node
func GetIPv6() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv6Address
}

// GetHostMasqueradeIPv6 returns the IPv6 address to be used for masquerading
// any traffic that is being forwarded from the host into the Cilium cluster.
func GetHostMasqueradeIPv6() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv6Address
}

// GetIPv6Router returns the IPv6 address of the node
func GetIPv6Router() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv6RouterAddress
}

// SetIPv6Router returns the IPv6 address of the node
func SetIPv6Router(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv6RouterAddress = ip
	addrsMu.Unlock()
}

// SetK8sExternalIPv6 sets the external IPv6 node address. It must be a public IP.
func SetK8sExternalIPv6(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv6ExternalAddress = ip
	addrsMu.Unlock()
}

// GetK8sExternalIPv6 returns the external IPv6 node address.
func GetK8sExternalIPv6() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv6ExternalAddress
}

// GetNodeAddressing returns the NodeAddressing model for the local IPs.
func GetNodeAddressing() *models.NodeAddressing {
	a := &models.NodeAddressing{}

	if option.Config.EnableIPv6 {
		a.IPV6 = &models.NodeAddressingElement{
			Enabled:    option.Config.EnableIPv6,
			IP:         GetIPv6Router().String(),
			AllocRange: GetIPv6AllocRange().String(),
		}
	}

	if option.Config.EnableIPv4 {
		a.IPV4 = &models.NodeAddressingElement{
			Enabled:    option.Config.EnableIPv4,
			IP:         GetInternalIPv4Router().String(),
			AllocRange: GetIPv4AllocRange().String(),
		}
	}

	return a
}

func getCiliumHostIPsFromFile(nodeConfig string) (ipv4GW, ipv6Router net.IP) {
	// ipLen is the length of the IP address stored in the node_config.h
	// it has the same length for both IPv4 and IPv6.
	const ipLen = net.IPv6len

	var hasIPv4, hasIPv6 bool
	f, err := os.Open(nodeConfig)
	switch {
	case err != nil:
	default:
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			txt := scanner.Text()
			switch {
			case !hasIPv6 && strings.Contains(txt, defaults.RestoreV6Addr):
				defineLine := strings.Split(txt, defaults.RestoreV6Addr)
				if len(defineLine) != 2 {
					continue
				}
				ipv6 := common.C2GoArray(defineLine[1])
				if len(ipv6) != ipLen {
					continue
				}
				ipv6Router = net.IP(ipv6)
				hasIPv6 = true
			case !hasIPv4 && strings.Contains(txt, defaults.RestoreV4Addr):
				defineLine := strings.Split(txt, defaults.RestoreV4Addr)
				if len(defineLine) != 2 {
					continue
				}
				ipv4 := common.C2GoArray(defineLine[1])
				if len(ipv4) != ipLen {
					continue
				}
				ipv4GW = net.IP(ipv4)
				hasIPv4 = true

			// Legacy cases based on the header defines:
			case !hasIPv4 && strings.Contains(txt, "IPV4_GATEWAY"):
				// #define IPV4_GATEWAY 0xee1c000a
				defineLine := strings.Split(txt, " ")
				if len(defineLine) != 3 {
					continue
				}
				ipv4GWHex := strings.TrimPrefix(defineLine[2], "0x")
				ipv4GWUint64, err := strconv.ParseUint(ipv4GWHex, 16, 32)
				if err != nil {
					continue
				}
				if ipv4GWUint64 != 0 {
					bs := make([]byte, net.IPv4len)
					byteorder.Native.PutUint32(bs, uint32(ipv4GWUint64))
					ipv4GW = net.IPv4(bs[0], bs[1], bs[2], bs[3])
					hasIPv4 = true
				}
			case !hasIPv6 && strings.Contains(txt, " ROUTER_IP "):
				// #define ROUTER_IP 0xf0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8a, 0xd6
				defineLine := strings.Split(txt, " ROUTER_IP ")
				if len(defineLine) != 2 {
					continue
				}
				ipv6 := common.C2GoArray(defineLine[1])
				if len(ipv6) != net.IPv6len {
					continue
				}
				ipv6Router = net.IP(ipv6)
				hasIPv6 = true
			}
		}
	}
	return ipv4GW, ipv6Router
}

// getCiliumHostIPs returns the Cilium IPv4 gateway and router IPv6 address from
// the node_config.h file if is present; or by deriving it from
// defaults.HostDevice interface, on which only the IPv4 is possible to derive.
func getCiliumHostIPs() (ipv4GW, ipv6Router net.IP) {
	nodeConfig := option.Config.GetNodeConfigPath()
	ipv4GW, ipv6Router = getCiliumHostIPsFromFile(nodeConfig)
	if ipv4GW != nil || ipv6Router != nil {
		log.WithFields(logrus.Fields{
			"ipv4": ipv4GW,
			"ipv6": ipv6Router,
			"file": nodeConfig,
		}).Info("Restored router address from node_config")
		return ipv4GW, ipv6Router
	}
	return getCiliumHostIPsFromNetDev(defaults.HostDevice)
}

// SetIPsecKeyIdentity sets the IPsec key identity an opaque value used to
// identity encryption keys used on the node.
func SetIPsecKeyIdentity(id uint8) {
	addrsMu.Lock()
	addrs.ipsecKeyIdentity = id
	addrsMu.Unlock()
}

// GetIPsecKeyIdentity returns the IPsec key identity of the node
func GetIPsecKeyIdentity() uint8 {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipsecKeyIdentity
}

// GetK8sNodeIPs returns k8s Node IP addr.
func GetK8sNodeIP() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.k8sNodeIP
}

// SetK8sNodeIP sets k8s Node IP addr.
func SetK8sNodeIP(ip net.IP) {
	addrsMu.Lock()
	addrs.k8sNodeIP = ip
	addrsMu.Unlock()
}

func SetWireguardPubKey(key string) {
	addrsMu.Lock()
	addrs.wireguardPubKey = key
	addrsMu.Unlock()
}

func GetWireguardPubKey() string {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.wireguardPubKey
}

// SetEndpointHealthIPv4 sets the IPv6 cilium-health endpoint address.
func SetEndpointHealthIPv4(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv4HealthIP = ip
	addrsMu.Unlock()
}

// GetEndpointHealthIPv4 returns the IPv4 cilium-health endpoint address.
func GetEndpointHealthIPv4() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv4HealthIP
}

// SetEndpointHealthIPv6 sets the IPv6 cilium-health endpoint address.
func SetEndpointHealthIPv6(ip net.IP) {
	addrsMu.Lock()
	addrs.ipv6HealthIP = ip
	addrsMu.Unlock()
}

// GetEndpointHealthIPv6 returns the IPv6 cilium-health endpoint address.
func GetEndpointHealthIPv6() net.IP {
	addrsMu.RLock()
	defer addrsMu.RUnlock()
	return addrs.ipv6HealthIP
}

func copyStringToNetIPMap(in map[string]net.IP) map[string]net.IP {
	out := make(map[string]net.IP, len(in))
	for iface, ip := range in {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		out[iface] = dup
	}
	return out
}
