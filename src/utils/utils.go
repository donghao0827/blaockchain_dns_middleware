package utils;

import (
    "encoding/binary"
    "strings"
    "strconv"
    "bytes"
    "log"
)

func BytesToInt(b byte)(num int) {
    return int(binary.BigEndian.Uint16([]byte{0, b}))
}

//域名字符串转btye数组
func ParseDomainName(domain string) []byte {
	var (
		buffer		bytes.Buffer
		segments	[]string = strings.Split(domain, ".")
	)
	for _, seg := range segments {
		binary.Write(&buffer, binary.BigEndian, byte(len(seg)))
		binary.Write(&buffer, binary.BigEndian, []byte(seg))
	}
	binary.Write(&buffer, binary.BigEndian, byte(0x00))
	return buffer.Bytes()
}

func ParseBytesToDomainName(bytes []byte) string {
    i, j := 0, 0
    var domainArr []string
    var domainName string
	for bytes[i] != 0 {
        length :=  BytesToInt(bytes[i])
        domainArr = append(domainArr, string(bytes[i + 1: i + 1 + length]))
        i = i + length + 1
        j++
    }
    domainName = strings.Join(domainArr, ".")
    return domainName
}

//IPv4地址转整型
func ParseIPv4(ip string) uint32 {
    var (
        segments    []string = strings.Split(ip, ".")
    )
    var sum uint32
    seg0, _ := strconv.Atoi(segments[0])
    seg1, _ := strconv.Atoi(segments[1])
    seg2, _ := strconv.Atoi(segments[2])
    seg3, _ := strconv.Atoi(segments[3])

    sum += uint32(seg0) << 24
    sum += uint32(seg1) << 16
    sum += uint32(seg2) << 8
    sum += uint32(seg3)
    return sum
}

//检错
func ChkErr(err error) {
    if err != nil {
        log.Fatal(err)
    }
}