package main

import (
	"net"

	"go-shadowsocks/pfutil"
	"go-shadowsocks/socks"
)

func redirLocal(addr, server string, shadow func(net.Conn) net.Conn) {
	tcpLocal(addr, server, shadow, natLookup)
}

func redir6Local(addr, server string, shadow func(net.Conn) net.Conn) {
	panic("TCP6 redirect not supported")
}

func natLookup(c net.Conn) (socks.Addr, error) {
	if tc, ok := c.(*net.TCPConn); ok {
		addr, err := pfutil.NatLookup(tc)
		return socks.ParseAddr(addr.String()), err
	}
	panic("not TCP connection")
}
