//go:build !mobile
// +build !mobile

package tun

import (
    "net"

    "github.com/vishvananda/netlink"
    wgtun "golang.zx2c4.com/wireguard/tun"
)

// Configures the TUN adapter with the correct IPv6 address and MTU.
func (tun *TunAdapter) setup(ifname string, addr string, mtu uint64) error {
    if ifname == "auto" {
        ifname = "\000"
    }
    iface, err := wgtun.CreateTUN(ifname, int(mtu))
    if err != nil {
        panic(err)
    }
    tun.iface = iface
    if mtu, err := iface.MTU(); err == nil {
        tun.mtu = getSupportedMTU(uint64(mtu))
    } else {
        tun.mtu = 0
    }
    if err := tun.setupAddress(addr); err != nil {
        return err
    }

    // Setup routes
    if err := tun.setupV4Routes(); err != nil {
        return err
    }
    if err := tun.setupV6Routes(); err != nil {
        return err
    }
    return nil
}

// Configures the TUN adapter with the correct IPv6 address and MTU.
func (tun *TunAdapter) setupAddress(addr string) error {
    nlintf, err := netlink.LinkByName(tun.Name())
    if err != nil {
        return err
    }

    // Add IPv6 address
    nladdr6, err := netlink.ParseAddr(addr)
    if err != nil {
        return err
    }
    if err := netlink.AddrAdd(nlintf, nladdr6); err != nil {
        return err
    }

    // Generate and add IPv4 address
    ip := nladdr6.IP.To16()
    ip[0] = 10
    ipv4 := net.IPv4(ip[0], ip[1], ip[2], ip[3]>>1+1)
    nladdr4, err := netlink.ParseAddr(ipv4.String() + "/8")
    if err != nil {
        tun.log.Errorf("Could not assign IPv4 address: %s", ipv4.String())
        return err
    }
    if err := netlink.AddrAdd(nlintf, nladdr4); err != nil {
        return err
    }

    // Set MTU and bring interface up
    if err := netlink.LinkSetMTU(nlintf, int(tun.mtu)); err != nil {
        return err
    }
    if err := netlink.LinkSetUp(nlintf); err != nil {
        return err
    }

    // Add default routes with metric 1000
    defaultRouteV4 := &netlink.Route{
        LinkIndex: nlintf.Attrs().Index,
        Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
        Priority:  1000,
    }
    if err := netlink.RouteAdd(defaultRouteV4); err != nil {
        tun.log.Warnf("Failed to add default IPv4 route: %v", err)
    }

    defaultRouteV6 := &netlink.Route{
        LinkIndex: nlintf.Attrs().Index,
        Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
        Priority:  1000,
    }
    if err := netlink.RouteAdd(defaultRouteV6); err != nil {
        tun.log.Warnf("Failed to add default IPv6 route: %v", err)
    }

    tun.log.Infof("Interface name: %s", tun.Name())
    tun.log.Infof("Interface IPv6: %s", addr)
    tun.log.Infof("Interface MTU: %d", tun.mtu)
    return nil
}

func (tun *TunAdapter) setupV4Routes() error {
    nlintf, err := netlink.LinkByName(tun.Name())
    if err != nil {
        return err
    }

    for _, r := range tun.rwc.V4Routes() {
        route := &netlink.Route{
            LinkIndex: nlintf.Attrs().Index,
            Dst: &net.IPNet{
                IP:   net.IP(r.Prefix.Addr().AsSlice()),
                Mask: net.CIDRMask(r.Prefix.Bits(), 32),
            },
            Priority: r.Metric,
        }
        if err := netlink.RouteAdd(route); err != nil {
            return err
        }
    }
    return nil
}

func (tun *TunAdapter) setupV6Routes() error {
    nlintf, err := netlink.LinkByName(tun.Name())
    if err != nil {
        return err
    }

    for _, r := range tun.rwc.V6Routes() {
        route := &netlink.Route{
            LinkIndex: nlintf.Attrs().Index,
            Dst: &net.IPNet{
                IP:   net.IP(r.Prefix.Addr().AsSlice()),
                Mask: net.CIDRMask(r.Prefix.Bits(), 128),
            },
            Priority: r.Metric,
        }
        if err := netlink.RouteAdd(route); err != nil {
            return err
        }
    }
    return nil
}
