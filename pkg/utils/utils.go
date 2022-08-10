package utils

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var (
	sriovConfigured = "/sriov_numvfs"
	// NetDirectory sysfs net directory
	NetDirectory = "/sys/class/net"
	// SysBusPci is sysfs pci device directory
	SysBusPci = "/sys/bus/pci/devices"
	// SysV4ArpNotify is the sysfs IPv4 ARP Notify directory
	SysV4ArpNotify = "/proc/sys/net/ipv4/conf/"
	// SysV6NdiscNotify is the sysfs IPv6 Neighbor Discovery Notify directory
	SysV6NdiscNotify = "/proc/sys/net/ipv6/conf/"
	// UserspaceDrivers is a list of driver names that don't have netlink representation for their devices
	UserspaceDrivers = []string{"vfio-pci", "uio_pci_generic", "igb_uio"}
)

// EnableArpAndNdiscNotify enables IPv4 arp_notify and IPv6 ndisc_notify for VF
func EnableArpAndNdiscNotify(ifName string) error {
	/* For arp_notify, when a value of "1" is set then a Gratuitous ARP request will be sent
	 * when the network device is brought up or if the link-layer address changes.
	 * For ndsic_notify, when a value of "1" is set then a Unsolicited Neighbor Advertisement
	 * will be sent when the network device is brought up or if the link-layer address changes.
	 * Both of these being enabled would be useful in the case when an application reenables
	 * an interface or if the MAC address configuration is changed. The kernel is responsible
	 * for sending of these packets when the conditions are met.
	 */
	v4ArpNotifyPath := filepath.Join(SysV4ArpNotify, ifName, "arp_notify")
	err := ioutil.WriteFile(v4ArpNotifyPath, []byte("1"), os.ModeAppend)
	if err != nil {
		return fmt.Errorf("failed to write arp_notify=1 for interface %s: %v", ifName, err)
	}
	v6NdiscNotifyPath := filepath.Join(SysV6NdiscNotify, ifName, "ndisc_notify")
	err = ioutil.WriteFile(v6NdiscNotifyPath, []byte("1"), os.ModeAppend)
	if err != nil {
		return fmt.Errorf("failed to write ndisc_notify=1 for interface %s: %v", ifName, err)
	}
	return nil
}

// GetSriovNumVfs takes in a PF name(ifName) as string and returns number of VF configured as int
func GetSriovNumVfs(ifName string) (int, error) {
	var vfTotal int

	sriovFile := filepath.Join(NetDirectory, ifName, "device", sriovConfigured)
	if _, err := os.Lstat(sriovFile); err != nil {
		return vfTotal, fmt.Errorf("failed to open the sriov_numfs of device %q: %v", ifName, err)
	}

	data, err := ioutil.ReadFile(sriovFile)
	if err != nil {
		return vfTotal, fmt.Errorf("failed to read the sriov_numfs of device %q: %v", ifName, err)
	}

	if len(data) == 0 {
		return vfTotal, fmt.Errorf("no data in the file %q", sriovFile)
	}

	sriovNumfs := strings.TrimSpace(string(data))
	vfTotal, err = strconv.Atoi(sriovNumfs)
	if err != nil {
		return vfTotal, fmt.Errorf("failed to convert sriov_numfs(byte value) to int of device %q: %v", ifName, err)
	}

	return vfTotal, nil
}

// GetVfid takes in VF's PCI address(addr) and pfName as string and returns VF's ID as int
func GetVfid(addr string, pfName string) (int, error) {
	var id int
	vfTotal, err := GetSriovNumVfs(pfName)
	if err != nil {
		return id, err
	}
	for vf := 0; vf < vfTotal; vf++ {
		vfDir := filepath.Join(NetDirectory, pfName, "device", fmt.Sprintf("virtfn%d", vf))
		_, err := os.Lstat(vfDir)
		if err != nil {
			continue
		}
		pciinfo, err := os.Readlink(vfDir)
		if err != nil {
			continue
		}
		pciaddr := filepath.Base(pciinfo)
		if pciaddr == addr {
			return vf, nil
		}
	}
	return id, fmt.Errorf("unable to get VF ID with PF: %s and VF pci address %v", pfName, addr)
}

// GetPfName returns PF net device name of a given VF pci address
func GetPfName(vf string) (string, error) {
	pfSymLink := filepath.Join(SysBusPci, vf, "physfn", "net")
	_, err := os.Lstat(pfSymLink)
	if err != nil {
		return "", err
	}

	files, err := ioutil.ReadDir(pfSymLink)
	if err != nil {
		return "", err
	}

	if len(files) < 1 {
		return "", fmt.Errorf("PF network device not found")
	}

	return strings.TrimSpace(files[0].Name()), nil
}

// GetPciAddress takes in a interface(ifName) and VF id and returns returns its pci addr as string
func GetPciAddress(ifName string, vf int) (string, error) {
	var pciaddr string
	vfDir := filepath.Join(NetDirectory, ifName, "device", fmt.Sprintf("virtfn%d", vf))
	dirInfo, err := os.Lstat(vfDir)
	if err != nil {
		return pciaddr, fmt.Errorf("can't get the symbolic link of virtfn%d dir of the device %q: %v", vf, ifName, err)
	}

	if (dirInfo.Mode() & os.ModeSymlink) == 0 {
		return pciaddr, fmt.Errorf("No symbolic link for the virtfn%d dir of the device %q", vf, ifName)
	}

	pciinfo, err := os.Readlink(vfDir)
	if err != nil {
		return pciaddr, fmt.Errorf("can't read the symbolic link of virtfn%d dir of the device %q: %v", vf, ifName, err)
	}

	pciaddr = filepath.Base(pciinfo)
	return pciaddr, nil
}

// GetSharedPF takes in VF name(ifName) as string and returns the other VF name that shares same PCI address as string
func GetSharedPF(ifName string) (string, error) {
	pfName := ""
	pfDir := filepath.Join(NetDirectory, ifName)
	dirInfo, err := os.Lstat(pfDir)
	if err != nil {
		return pfName, fmt.Errorf("can't get the symbolic link of the device %q: %v", ifName, err)
	}

	if (dirInfo.Mode() & os.ModeSymlink) == 0 {
		return pfName, fmt.Errorf("No symbolic link for dir of the device %q", ifName)
	}

	fullpath, _ := filepath.EvalSymlinks(pfDir)
	parentDir := fullpath[:len(fullpath)-len(ifName)]
	dirList, _ := ioutil.ReadDir(parentDir)

	for _, file := range dirList {
		if file.Name() != ifName {
			pfName = file.Name()
			return pfName, nil
		}
	}

	return pfName, fmt.Errorf("Shared PF not found")
}

// GetVFLinkNames returns VF's network interface name given it's PCI addr
func GetVFLinkNames(pciAddr string) (string, error) {
	var names []string
	vfDir := filepath.Join(SysBusPci, pciAddr, "net")
	if _, err := os.Lstat(vfDir); err != nil {
		return "", err
	}

	fInfos, err := ioutil.ReadDir(vfDir)
	if err != nil {
		return "", fmt.Errorf("failed to read net dir of the device %s: %v", pciAddr, err)
	}

	if len(fInfos) == 0 {
		return "", fmt.Errorf("VF device %s sysfs path (%s) has no entries", pciAddr, vfDir)
	}

	names = make([]string, 0)
	for _, f := range fInfos {
		names = append(names, f.Name())
	}

	return names[0], nil
}

// GetVFLinkNamesFromVFID returns VF's network interface name given it's PF name as string and VF id as int
func GetVFLinkNamesFromVFID(pfName string, vfID int) ([]string, error) {
	var names []string
	vfDir := filepath.Join(NetDirectory, pfName, "device", fmt.Sprintf("virtfn%d", vfID), "net")
	if _, err := os.Lstat(vfDir); err != nil {
		return nil, err
	}

	fInfos, err := ioutil.ReadDir(vfDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read the virtfn%d dir of the device %q: %v", vfID, pfName, err)
	}

	names = make([]string, 0)
	for _, f := range fInfos {
		names = append(names, f.Name())
	}

	return names, nil
}

// HasDpdkDriver checks if a device is attached to dpdk supported driver
func HasDpdkDriver(pciAddr string) (bool, error) {
	driverLink := filepath.Join(SysBusPci, pciAddr, "driver")
	driverPath, err := filepath.EvalSymlinks(driverLink)
	if err != nil {
		return false, err
	}
	driverStat, err := os.Stat(driverPath)
	if err != nil {
		return false, err
	}
	driverName := driverStat.Name()
	for _, drv := range UserspaceDrivers {
		if driverName == drv {
			return true, nil
		}
	}
	return false, nil
}

// SaveNetConf takes in container ID, data dir and Pod interface name as string and a json encoded struct Conf
// and save this Conf in data dir
func SaveNetConf(cid, dataDir, podIfName string, conf interface{}) error {
	netConfBytes, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	s := []string{cid, podIfName}
	cRef := strings.Join(s, "-")

	// save the rendered netconf for cmdDel
	if err = saveScratchNetConf(cRef, dataDir, netConfBytes); err != nil {
		return err
	}

	return nil
}

func saveScratchNetConf(containerID, dataDir string, netconf []byte) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create the sriov data directory(%q): %v", dataDir, err)
	}

	path := filepath.Join(dataDir, containerID)

	err := ioutil.WriteFile(path, netconf, 0600)
	if err != nil {
		return fmt.Errorf("failed to write container data in the path(%q): %v", path, err)
	}

	return err
}

// ReadScratchNetConf takes in container ID, Pod interface name and data dir as string and returns a pointer to Conf
func ReadScratchNetConf(cRefPath string) ([]byte, error) {
	data, err := ioutil.ReadFile(cRefPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read container data in the path(%q): %v", cRefPath, err)
	}

	return data, err
}

// CleanCachedNetConf removed cached NetConf from disk
func CleanCachedNetConf(cRefPath string) error {
	if err := os.Remove(cRefPath); err != nil {
		return fmt.Errorf("error removing NetConf file %s: %q", cRefPath, err)
	}
	return nil
}

// htons converts an uint16 from host to network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// SendGratuitousArp sends a gratuitous ARP packet with the provided source IP over the provided interface.
func SendGratuitousArp(srcIP net.IP, iface net.Interface) error {
	/* As per RFC 5944 section 4.6, a gratuitous ARP packet can be sent by a node in order to spontaneously cause other nodes to update
	 * an entry in their ARP cache. In the case of SRIOV-CNI, an address can be reused for different pods. Each pod could likely have a
	 * different link-layer address in this scenario, which makes the ARP cache entries residing in the other nodes to be an invalid.
	 * The gratuitous ARP packet should update the link-layer address accordingly for the invalid ARP cache.
	 */

	// Construct the ARP packet following RFC 5944 section 4.6.
	arpPacket := new(bytes.Buffer)
	_ = binary.Write(arpPacket, binary.BigEndian, uint16(1))                 // Hardware Type: 1 is Ethernet
	_ = binary.Write(arpPacket, binary.BigEndian, uint16(syscall.ETH_P_IP))  // Protocol Type: 0x0800 is IPv4
	_ = binary.Write(arpPacket, binary.BigEndian, uint8(6))                  // Hardware address Length: 6 bytes for MAC address
	_ = binary.Write(arpPacket, binary.BigEndian, uint8(4))                  // Protocol address length: 4 bytes for IPv4 address
	_ = binary.Write(arpPacket, binary.BigEndian, uint16(1))                 // Operation: 1 is request, 2 is response
	if _, writeErr := arpPacket.Write(iface.HardwareAddr); writeErr != nil { // Sender hardware address
		return fmt.Errorf("failed to write the hardware address in the ARP packet: %v", writeErr)
	}
	if _, writeErr := arpPacket.Write(srcIP.To4()); writeErr != nil { // Sender protocol address
		return fmt.Errorf("failed to write the sender protocol address in the ARP packet: %v", writeErr)
	}
	_, _ = arpPacket.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // Target hardware address is the Broadcast MAC.
	if _, writeErr := arpPacket.Write(srcIP.To4()); writeErr != nil {  // Target protocol address
		return fmt.Errorf("failed to write the target protocol address in the ARP packet: %v", writeErr)
	}

	sockAddr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP),                                // Ethertype of ARP (0x0806)
		Ifindex:  iface.Index,                                             // Interface Index
		Hatype:   1,                                                       // Hardware Type: 1 is Ethernet
		Pkttype:  0,                                                       // Packet Type.
		Halen:    6,                                                       // Hardware address Length: 6 bytes for MAC address
		Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Address is the broadcast MAC address.
	}

	// Create a socket such that the Ethernet header would constructed by the OS. The arpPacket only contains the ARP payload.
	soc, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("failed to create AF_PACKET datagram socket: %v", err)
	}
	defer syscall.Close(soc)

	if err := syscall.Sendto(soc, arpPacket.Bytes(), 0, &sockAddr); err != nil {
		return fmt.Errorf("failed to send Gratuitous ARP for IPv4 %s on Interface %s: %v", srcIP.String(), iface.Name, err)
	}

	return nil
}

// SendUnsolicitedNeighborAdvertisement sends an unsolicited neighbor advertisement packet with the provided source IP over the provided interface.
func SendUnsolicitedNeighborAdvertisement(srcIP net.IP, iface net.Interface) error {
	/* As per RFC 4861, a link-layer address change can multicast a few unsolicited neighbor advertisements to all nodes to quickly
	 * update the cached link-layer addresses that have become invalid. In the case of SRIOV-CNI, an address can be reused for
	 * different pods. Each pod could likely have a different link-layer address in this scenario, which makes the Neighbor Cache
	 * entries residing in the neighbors to be an invalid. The unsolicited neighbor advertisement should update the link-layer address
	 * accordingly for the IPv6 entry.
	 * However if any of these conditions are true:
	 *  - The IPv6 address was not reused for the new pod.
	 *  - No prior established communication with the neighbor.
	 * Then the neighbor receiving this unsolicited neighbor advertisement would be silently discard. This behavior is described
	 * in RFC 4861 section 7.2.5. This is acceptable behavior since the purpose of sending an unsolicited neighbor advertisement
	 * is not to create a new entry but rather update already existing invalid entries.
	 */

	// Construct the ICMPv6 Neighbor Advertisement packet following RFC 4861.
	payload := new(bytes.Buffer)
	// ICMPv6 Flags: As per RFC 4861, the solicited flag must not be set and the override flag should be set (to
	// override existing cache entry) for unsolicited advertisements.
	_ = binary.Write(payload, binary.BigEndian, uint32(0x20000000))
	if _, writeErr := payload.Write(srcIP.To16()); writeErr != nil { // ICMPv6 Target IPv6 Address.
		return fmt.Errorf("failed to write the target IPv6 address in the ICMPv6 packet: %v", writeErr)
	}
	_ = binary.Write(payload, binary.BigEndian, uint8(2))                  // ICMPv6 Option Type: 2 is target link-layer address.
	_ = binary.Write(payload, binary.BigEndian, uint8(1))                  // ICMPv6 Option length. Units of 8 bytes.
	if _, writeErr := payload.Write(iface.HardwareAddr); writeErr != nil { // ICMPv6 Option Link-layer address.
		return fmt.Errorf("failed to write the link-layer address in the ICMPv6 packet: %v", writeErr)
	}

	icmpv6Msg := icmp.Message{
		Type:     ipv6.ICMPTypeNeighborAdvertisement, // ICMPv6 type is neighbor advertisement.
		Code:     0,                                  // ICMPv6 Code: As per RFC 4861 section 7.1.2, the code is always 0.
		Checksum: 0,                                  // Checksum is calculated later.
		Body: &icmp.RawBody{
			Data: payload.Bytes(),
		},
	}

	// Get the byte array of the ICMPv6 Message.
	icmpv6Bytes, err := icmpv6Msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to Marshal ICMPv6 Message: %v", err)
	}

	// Create a socket such that the Ethernet header and IPv6 header would constructed by the OS.
	soc, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return fmt.Errorf("failed to create AF_INET6 raw socket: %v", err)
	}
	defer syscall.Close(soc)

	// As per RFC 4861 section 7.1.2, the IPv6 hop limit is always 255.
	if err := syscall.SetsockoptInt(soc, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255); err != nil {
		return fmt.Errorf("failed to set IPv6 multicast hops to 255: %v", err)
	}

	// Set the destination IPv6 address to the IPv6 link-local all nodes multicast address (ff02::1).
	var r [16]byte
	copy(r[:], net.IPv6linklocalallnodes.To16())
	sockAddr := syscall.SockaddrInet6{Addr: r}
	if err := syscall.Sendto(soc, icmpv6Bytes, 0, &sockAddr); err != nil {
		return fmt.Errorf("failed to send Unsolicited Neighbor Advertisement for IPv6 %s on Interface %s: %v", srcIP.String(), iface.Name, err)
	}

	return nil
}
