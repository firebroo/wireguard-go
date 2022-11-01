package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/ipv4"
	"strconv"
	"strings"
	"sync"
	"golang.zx2c4.com/wireguard/rediscluster/connect"
	"time"
	"context"
)

const (
	TCP_TIMEOUT_CLOSE          = 10
	TCP_TIMEOUT_CLOSE_WAIT     = 60
	TCP_TIMEOUT_ESTABLISHED    = 432000
	TCP_TIMEOUT_FIN_WAIT       = 120
	TCP_TIMEOUT_LAST_ACK       = 30
	TCP_TIMEOUT_SYN_RECV       = 60
	TCP_TIMEOUT_SYN_SENT       = 120
	TCP_TIMEOUT_TIME_WAIT      = 120
	TCP_TIMEOUT_UNACKNOWLEDGED = 300
	UDP_TIMEOUT                = 30
	UDP_TIMEOUT_STREAM         = 180
	ICMP_TIMEOUT               = 30
)

const (
	URG = 0x20
	ACK = 0x10
	PSH = 0x08
	RST = 0x04
	SYN = 0x02
	FIN = 0x01
)

type TcpSession struct {
	ValidDate int
	TcpStage  string
	srcIp     string
}

var m sync.Map

func clearNatTable() {
	for {
		m.Range(func(k, v interface{}) bool {
			tmp := v.(TcpSession).ValidDate - 2
			fmt.Printf("%s={%d, %s}\n", k, tmp, v.(TcpSession).TcpStage)
			if tmp <= 0 {
				fmt.Printf("delete\n")
				m.Delete(k)
			} else {
				m.Store(k, TcpSession{tmp, v.(TcpSession).TcpStage, v.(TcpSession).srcIp})
			}
			return true
		})
		fmt.Printf("%v\n", m)
		time.Sleep(2 * time.Second)
	}
}

func init() {
	go clearNatTable()
}

func IPv4CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)

	//以每16位为单位进行求和，直到所有的字节全部求完或者只剩下一个8位字节（如果剩余一个8位字节说明字节数为奇数个）
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	//如果字节数为奇数个，要加上最后剩下的那个8位字节
	if length > 0 {
		sum += uint32(data[index]) << 8
	}
	//加上高16位进位的部分
	sum += (sum >> 16)
	//别忘了返回的时候先求反
	return uint16(^sum)
}

func IntToBytes(intNum uint16) []byte {
	uint16Num := uint16(intNum)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, uint16Num)
	return buf.Bytes()
}


func (device *Device) parse_tcp_flag(flag byte) (int, string) {
	urg := (flag & URG) == URG
	ack := (flag & ACK) == ACK
	psh := (flag & PSH) == PSH
	rst := (flag & RST) == RST
	syn := (flag & SYN) == SYN
	fin := (flag & FIN) == FIN
	device.log.Verbosef("urg=%t, ack=%t, psh=%t, rst=%t, syn=%t, fin=%t", urg, ack, psh, rst, syn, fin)
	if rst {
		return 0, "rst_set"
	}
	if syn {
		if !ack {
			return TCP_TIMEOUT_SYN_SENT, "syn_sent_set"
		}
		return TCP_TIMEOUT_SYN_RECV, "syn_ack_set"
	}
	if fin {
		return TCP_TIMEOUT_FIN_WAIT, "fin_wait_set"
	}
	if ack {
		return TCP_TIMEOUT_ESTABLISHED, "established_set"
	}
	return 0, "unknown"
}

// ip头checksum重新计算
func ipCheckSumReplace(packet []byte) {
	var checkSumStart int = 10
	iphar := packet[:20]
	copy(iphar[checkSumStart:], []byte{0x00, 0x00})
	newSum := IPv4CheckSum(iphar)
	newSumBytes := IntToBytes(newSum)
	copy(iphar[checkSumStart:], newSumBytes[0:2])
}

/*
复制源地址和目标地址，构造伪IP头

	源ip头     4字节
	目的ip头   4字节
	0x00 协议号 tcp/udp长度 4字节
*/
func makeFlaseIPHeader(ip []byte, protocol byte, _len uint16) []byte {
	var byteStream [2048]byte

	copy(byteStream[0:8], ip)
	byteStream[8] = 0x00
	byteStream[9] = protocol
	dataLen := IntToBytes(uint16(_len))
	copy(byteStream[10:], dataLen[0:2])
	return byteStream[:]
}

func udpTcpCheckSumReplace(packet []byte, protocol byte, _len uint16) {
	var checkSumStart int
	switch protocol {
	case 0x06:
		checkSumStart = 16
	case 0x11:
		checkSumStart = 6
	default:
		return
	}
	tcpOrUdpHeader := makeFlaseIPHeader(packet[12:20], protocol, _len)
	//将tcp checksum替换为0
	copy(packet[20+checkSumStart:], []byte{0x00, 0x00})
	//拷贝tcp data，IP头长度为20
	copy(tcpOrUdpHeader[12:], packet[20:20+_len])
	newSum := IPv4CheckSum(tcpOrUdpHeader[:_len+12])
	newSumBytes := IntToBytes(newSum)
	copy(packet[20+checkSumStart:], newSumBytes[0:2])
}

func makeDNatTableKey(hdr *ipv4.Header, packet []byte, streamDirect string) string {
	var key string
	switch hdr.Protocol {
	case 0x01:
		identifier_byte := packet[24:26]
		identifier := binary.BigEndian.Uint16(identifier_byte)
		if streamDirect == "in" {
			key = fmt.Sprintf("%d-%s:%s:%d", hdr.Protocol, hdr.Src, hdr.Dst, identifier)
		}
		if streamDirect == "out" {
			key = fmt.Sprintf("%d-%s:%s:%d", hdr.Protocol, hdr.Dst, hdr.Src, identifier)
		}
	case 0x06, 0x11:
		sportBytes := packet[20:22]
		dportBytes := packet[22:24]
		sport := binary.BigEndian.Uint16(sportBytes)
		dport := binary.BigEndian.Uint16(dportBytes)
		if streamDirect == "in" {
			key = fmt.Sprintf("%d-%s:%d-%s:%d", hdr.Protocol, hdr.Src, sport, hdr.Dst, dport)
		}
		if streamDirect == "out" {
			key = fmt.Sprintf("%d-%s:%d-%s:%d", hdr.Protocol, hdr.Dst, dport, hdr.Src, sport)
		}
	}
	return key
}

func (device *Device) HandlerReceiveIpv4Stream(src, dst string, elem *QueueInboundElement, _len uint16) bool {
	cmd := connect.Cluster.Get(context.TODO(), dst)

	result, err := cmd.Result()
	if err != nil {
		return false
	}
	ipBytes, err := stringIpToByte(result)
	if err != nil {
		return false
	}
	//目标地址替换
	copy(elem.packet[IPv4offsetDst:], ipBytes)
	ipCheckSumReplace(elem.packet[:])

	hdr, err := ipv4.ParseHeader(elem.packet[:])
	if err != nil {
		device.log.Verbosef("err")
	}
	key := makeDNatTableKey(hdr, elem.packet[:], "in")
	switch hdr.Protocol {
	case 0x01:
		m.Store(key, TcpSession{ICMP_TIMEOUT, "icmp_timeout_set", dst})
	case 0x06:
		udpTcpCheckSumReplace(elem.packet[:], byte(hdr.Protocol), _len)
		validDate, stage := device.parse_tcp_flag(elem.packet[20+13])
		v, ok := m.LoadOrStore(key, TcpSession{validDate, stage, dst})
		if !ok {
			return false
		}
		if v.(TcpSession).TcpStage == "fin_wait_set" && validDate == TCP_TIMEOUT_ESTABLISHED {
			m.Store(key, TcpSession{TCP_TIMEOUT_TIME_WAIT, "time_wait_set", dst})
		} else {
			m.Store(key, TcpSession{validDate, stage, dst})
		}
	case 0x11:
		udpTcpCheckSumReplace(elem.packet[:], byte(hdr.Protocol), _len)
		m.Store(key, TcpSession{UDP_TIMEOUT, "udp_timeout_set", dst})
	default:
		return false
	}
	return false
}

func stringIpToByte(ip string) ([]byte, error) {
	var ipBytes []byte
	ips := strings.Split(ip, ".")
	for _, i := range ips {
		x, err := strconv.Atoi(i)
		if err != nil {
			return ipBytes, err
		}
		ipBytes = append(ipBytes, byte(x))
	}
	return ipBytes, nil
}

func (device *Device) HandlerSendIpv4Stream(src, dst string, elem *QueueOutboundElement, _len uint16) bool {
	hdr, err := ipv4.ParseHeader(elem.packet[:])
	if err != nil {
		device.log.Verbosef("err")
	}
	key := makeDNatTableKey(hdr, elem.packet[:], "out")
	vv, ok := m.Load(key)
	if !ok {
		device.log.Verbosef("key=%s, skip", key)
		return false
	}
	srcIp := vv.(TcpSession).srcIp
	ipBytes, err := stringIpToByte(srcIp)
	if err != nil {
		return false
	}
	copy(elem.packet[IPv4offsetSrc:], ipBytes)
	ipCheckSumReplace(elem.packet[:])
	switch hdr.Protocol {
	case 0x01:
	case 0x06:
		udpTcpCheckSumReplace(elem.packet[:], byte(hdr.Protocol), _len)
		validDate, stage := device.parse_tcp_flag(elem.packet[20+13])
		v, ok := m.LoadOrStore(key, TcpSession{validDate, stage, srcIp})
		if !ok {
			return false
		}
		if v.(TcpSession).TcpStage == "fin_wait_set" && validDate == TCP_TIMEOUT_ESTABLISHED {
			m.Store(key, TcpSession{TCP_TIMEOUT_TIME_WAIT, "time_wait_set", srcIp})
		} else {
			m.Store(key, TcpSession{validDate, stage, srcIp})
		}
	case 0x11:
		udpTcpCheckSumReplace(elem.packet[:], byte(hdr.Protocol), _len)
	}
	return false
}
