package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var opcode = flag.Uint("opcode", 254, "opcode of Tcp Option Address")
var port = flag.Uint("port", 80, "port of Tcp Option Address")
var ipStr = flag.String("ip", "8.8.8.8", "ip of Tcp Option Address that you want to fake")

func main() {
	flag.Parse()
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	log.SetFlags(0)
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {

		log.Fatal("Removing memlock:", err)
	}
	spec, err := loadFakeip()
	if err != nil {
		log.Fatal("load profile connect error", err)
	}
	ip := ipToIntLittle(*ipStr)
	//log.Println(ip)
	err = spec.RewriteConstants(map[string]interface{}{
		"opcode": (uint8)(*opcode),
		"port":   (uint16)(*port),
		"ip":     ip,
	})
	if err != nil {
		log.Fatal("rewrite constants error,", err)
	}

	objs := fakeipObjects{}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatal("LoadAndAssign error,", err)
	}

	defer objs.Close()
	cgroup, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.BpfSockopsHandler,
	})
	defer cgroup.Close()

	go debug()
	<-stopper
}

func debug() {
	// 打开trace_pipe文件
	file, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Fatalf("Failed to open trace_pipe: %v", err)
	}
	defer file.Close()

	// 使用bufio.Reader读取文件
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read from trace_pipe: %v", err)
		}

		// 打印从trace_pipe中读取的每一行
		fmt.Print(line)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIpBig(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
func intToIpLittle(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

// ipToInt converts an IPv4 address string to a uint32
// 用的是大端顺序
func ipToIntBig(ipStr string) uint32 {
	ipParts := strings.Split(ipStr, ".")
	if len(ipParts) != 4 {
		log.Fatal("invalid IP format")
	}

	var ipInt uint32

	for i, part := range ipParts {
		part = part[:]
		p, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			log.Fatal("parseuint error,", err)
		}
		ipInt |= uint32(p) << (8 * i)
	}
	return ipInt
}
func ipToIntLittle(ipStr string) uint32 {
	ipParts := strings.Split(ipStr, ".")
	if len(ipParts) != 4 {
		log.Fatal("invalid IP format")
	}

	var ipInt uint32

	for i, part := range ipParts {
		part = part[:]
		p, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			log.Fatal("parseuint error,", err)
		}
		ipInt |= uint32(p) << (8 * (3 - i))
	}
	return ipInt
}
