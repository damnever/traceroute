/*
A simple traceroute program written in Go.
*/
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	HOST      = "0.0.0.0"
	SEND_PORT = 33333
	RECV_PORT = 0
	TIMEOUT   = 5000
)

type ReturnArgs struct {
	ok      bool
	done    bool
	addr    string
	ip      string
	elapsed float64
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage:\n  sudo ./traceroute [options] <domain/ip>\nOptions:\n")
		flag.PrintDefaults()
	}
	maxTTL := flag.Int("m", 30, "Set the max number of hops (max TTL to be reached). Default is 30")
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		return
	}
	host := flag.Args()[0]

	addrs, err := net.LookupHost(host)
	if err != nil {
		exitWithError(err)
	}
	addr := addrs[0]
	fmt.Printf("traceroute to %v (%v), %v hops max\n", host, addr, *maxTTL)

	traceroute(addr, *maxTTL)
}

func traceroute(ip string, maxTTL int) {
	addr := toAddr(ip, SEND_PORT)
	done := false
	for ttl := 1; ttl <= maxTTL; ttl++ {
		info := fmt.Sprintf("%v  ", ttl)
		for i := 0; i < 3; i++ {
			rr := traceOne(addr, ttl)
			if rr.done {
				done = true // use break TAG?
			}
			if rr.ok {
				info += fmt.Sprintf("%v(%v) %vms", rr.addr, rr.ip, rr.elapsed)
			} else {
				info += "*"
			}
			if i != 2 {
				info += "   "
			}
		}
		fmt.Println(info)
		if done {
			break
		}
	}
}

func traceOne(addr *syscall.SockaddrInet4, ttl int) *ReturnArgs {
	cli, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		exitWithError(err)
	}
	srv, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		exitWithError(err)
	}

	defer syscall.Close(cli)
	defer syscall.Close(srv)

	// set ttl, stolen from somewhere else...
	// https://github.com/aeden/traceroute/blob/master/traceroute.go#L195
	if err := syscall.SetsockoptInt(cli, syscall.SOL_IP, syscall.IP_TTL, ttl); err != nil {
		exitWithError(err)
	}

	// set timeout, stolen from somewhere else...
	// https://github.com/aeden/traceroute/blob/master/traceroute.go#L197
	tv := syscall.NsecToTimeval(1e6 * TIMEOUT)
	if err := syscall.SetsockoptTimeval(srv, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		exitWithError(err)
	}
	if err := syscall.Bind(srv, toAddr(HOST, RECV_PORT)); err != nil {
		exitWithError(err)
	}

	rr := &ReturnArgs{}
	start := time.Now()
	if err := syscall.Sendto(cli, makeICMP(), 0, addr); err != nil {
		return rr
	}

	buf := make([]byte, 512)
	_, from, err := syscall.Recvfrom(srv, buf, 0)
	if err != nil {
		return rr
	}

	rr.elapsed = float64(time.Since(start).Nanoseconds()) / 1e6
	t, c := parseICMP(buf)
	if t == 3 && c == 3 { // Destination port unreachable, type==3 && code==3
		rr.done = true
	} else if t != 11 { // Time Exceeded, type==11 && code in (0,1)
		return rr
	}
	rr.ok = true
	rr.ip = toStr(from)
	addrs, err := net.LookupAddr(rr.ip)
	if err != nil {
		rr.addr = rr.ip
	} else {
		rr.addr = addrs[0]
	}
	return rr
}

func exitWithError(err error) {
	fmt.Printf("%v\n", err)
	os.Exit(1)
}

func toStr(addr syscall.Sockaddr) string {
	b := addr.(*syscall.SockaddrInet4).Addr
	return fmt.Sprintf("%v.%v.%v.%v", b[0], b[1], b[2], b[3])
}

func toAddr(addr string, port int) *syscall.SockaddrInet4 {
	b := net.ParseIP(addr).To4()
	return &syscall.SockaddrInet4{
		Port: port,
		Addr: [4]byte{b[0], b[1], b[2], b[3]},
	}
}

func parseICMP(value []byte) (int, int) {
	// 20bytes IP header
	v := value[20:22]
	return int(v[0]), int(v[1])
}

func makeICMP() []byte {
	icmp := []byte{
		8, 0, // echo request, 8bit: type=8, 8bit: code=0
		0, 0, // 16bit: check sum=0(init)
		0, 0, 0, 0, // 32bit: not used=0
	}
	cs := checkSum(icmp)
	icmp[2] = byte(cs)
	icmp[3] = byte(cs >> 8)
	return icmp
}

func checkSum(value []byte) uint16 {
	sum := uint32(0)

	for i, n := 0, len(value); i < n; i += 2 {
		sum += uint32(value[i+1]<<8) + uint32(value[i])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	return uint16(^sum)
}
