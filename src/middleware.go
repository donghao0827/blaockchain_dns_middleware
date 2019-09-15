package main;

import (
    "net"
    //"net/http"
    //"fmt"
    "log"
    "encoding/binary"
    "github.com/json-iterator/go"
    "strings"
    "bytes"
    //"encoding/json"
    "io/ioutil"
    "./utils"
    // "sync"
)

func chkError(err error) {
    if err != nil {
        log.Fatal(err)
    }
}

func byte2ToInt(b byte)(num int) {
    return int(binary.BigEndian.Uint16([]byte{0, b}))
}

//接受json数据结构体
type Response struct {
    Code  uint32
    Msg   string
    Data  ResBody
}

type ResBody struct {
    Auth_count     uint16
    Extra_count    uint16
    Auth_details   []DNSRecord
    Extra_details  []DNSRecord
}

type DNSRecord struct {
    Name      string
    Type      uint16
    Class     uint16
    TTL       uint32
    RDLength  uint16
    RData     RData
}

type RData struct {
    Addr	  string
    Name_server   string
}

//DNS消息头部
type DnsHeader struct {
	Id									uint16  //Message ID 2字节
    Flag								uint16  //头部内容 2字节
	Qdcount, Ancount, Nscount, Arcount	uint16  //标识计数 各2字节 Qdcount请求部分的条目数、Ancount相应部分资源记录数、Nscount权威部分域名资源记录数、Arcount额外部分资源记录数
}

func (header *DnsHeader) SetFlag(QR uint16, OperationCode uint16, AuthoritativeAnswer uint16, Truncation uint16, RecursionDesired uint16, RecursionAvailable uint16, ResponseCode uint16) {
    header.Flag = QR<<15 + OperationCode<<11 + AuthoritativeAnswer<<10 + Truncation<<9 + RecursionDesired<<8 + RecursionAvailable<<7 + ResponseCode
}
//Bits 包括QR 1bit 标识请求/应答、OPCODE 4bit 标识请求类型、 AA 1bit 只在响应中有效，标识是否为权威、TC 1bit 是否截断、RD 1bit 是否递归、RA 1bit 是否支持递归、 RCODE 4bit 只在响应中标注，标识响应消息类型

//请求部分
type QuerySection struct {
    QueryType   uint16
    QueryClass  uint16
}

//响应部分  (不含RDATA)
type ResponseSection struct {
    ResponseName        []byte
    ResponseType        uint16
    ResponseClass       uint16
    ResponseTTL         uint32
    ResponseRDLength    uint16
    ResponseRData       ResponseRData
}

//RDATA部分
type ResponseRData struct {
    ResponseAddr        uint32
    ResponseNameServer  []byte
}

//解析区块链返回数据
func ParseBlockResponse() (interface {}) {
	/*
    //发送http post请求
    client := &http.Client{}
    //request, _ := http.NewRequest("POST", "http://192.168.27.99:5002/query?url=www.qq.com&timestamp=178542318", nil)
    request, _ := http.NewRequest("POST", "http://localhost/server.php", nil)
    request.Header.Set("Content-type", "application/json")
    response, err := client.Do(request)
    chkError(err)
    var res Response
    var json = jsoniter.ConfigCompatibleWithStandardLibrary
    if response.StatusCode == 200 {
        body, _ := ioutil.ReadAll(response.Body)
        err := json.Unmarshal(body, &res)
        if err != nil {
            return false
        }
        return res
    }
    return false
    */
    bytes, errRead := ioutil.ReadFile("./data.json")
    chkError(errRead)
    var res Response
    var json = jsoniter.ConfigCompatibleWithStandardLibrary
    err := json.Unmarshal(bytes, &res)
    chkError(err)
    return res
}

//构建应答数据包
func BuildPacket(id uint16, queryName string, blockResponse ResBody) ([]byte){
    //响应头部
	responseHeader := DnsHeader {
		Id:			id,
		Qdcount:	1,
		Ancount:	0,
		Nscount:	blockResponse.Auth_count,
		Arcount:	blockResponse.Extra_count,
	}
    responseHeader.SetFlag(1, 0, 0, 0, 0, 0, 0)
    requestQuery := QuerySection {
        QueryType:  1,
        QueryClass:  1,
    }

    var buffer bytes.Buffer
    binary.Write(&buffer, binary.BigEndian, responseHeader)
    binary.Write(&buffer, binary.BigEndian, utils.ParseDomainName(queryName))
    binary.Write(&buffer, binary.BigEndian, requestQuery)
    binary.Write(&buffer, binary.BigEndian, BuildDNSRecord(blockResponse.Auth_details, queryName))
    binary.Write(&buffer, binary.BigEndian, BuildDNSRecord(blockResponse.Extra_details, queryName))
    //fmt.Println("resolve success!")
	return buffer.Bytes()
}

func BuildDNSRecord(details []DNSRecord, queryName string) []byte {
    var buffer bytes.Buffer
    for _, value := range details {
        rdata := value.RData
        responseName := value.Name
        var responseNameBytes []byte
        if strings.Contains(responseName, queryName) {
            responseNameBytes = utils.ParseDomainName(responseName);  //用指针代替，后续优化
        } else {
            responseNameBytes = utils.ParseDomainName(responseName);
        }

        var (
            ResponseRDLength        uint16
        )
        binary.Write(&buffer, binary.BigEndian, responseNameBytes)
        binary.Write(&buffer, binary.BigEndian, value.Type)
        binary.Write(&buffer, binary.BigEndian, value.Class)
        binary.Write(&buffer, binary.BigEndian, value.TTL)
        if value.Type == 2 {
            ResponseNameServerBytes := utils.ParseDomainName(rdata.Name_server)
            ResponseRDLength = uint16(len(ResponseNameServerBytes))
            binary.Write(&buffer, binary.BigEndian, ResponseRDLength)
            binary.Write(&buffer, binary.BigEndian, ResponseNameServerBytes)
        } else if  value.Type == 1 {
            ResponseAddrBytes := utils.ParseIPv4(rdata.Addr)
            ResponseRDLength = 4
            binary.Write(&buffer, binary.BigEndian, ResponseRDLength)
            binary.Write(&buffer, binary.BigEndian, ResponseAddrBytes)
        }
    }
    return buffer.Bytes()
}
func clientHandle(buf []byte, clientAddr *net.UDPAddr, conn *net.UDPConn) {
    //defer conn.Close()
    var id uint16
    bytesBuffer := (buf[0:2])
    buffer := bytes.NewReader(bytesBuffer)
    binary.Read(buffer, binary.BigEndian, &id)
    slice := buf[12:]
    i := 0
    j := 0
    var domainArr []string
    var domainName string
    for slice[i] != 0 {
        length :=  byte2ToInt(slice[i])
        domainArr = append(domainArr, string(slice[i + 1: i + 1 + length]))
        i = i + length + 1
        j++
    }
    domainName = strings.Join(domainArr, ".")
    //fmt.Println("from:", clientAddr, domainName)
    if ParseBlockResponse() != false {
        var response Response
        response = ParseBlockResponse().(Response)
        conn.WriteToUDP(BuildPacket(id, domainName, response.Data), clientAddr)
    }
}

func middleware(addr string) {
    udpaddr, err := net.ResolveUDPAddr("udp4", addr)
    chkError(err)
    //监听端口
    udpconn, err := net.ListenUDP("udp", udpaddr)
    chkError(err)
    //udp没有对客户端连接的Accept函数
    //buf := make([]byte, 256)
    for {
		buf := make([]byte, 256)
		_, clientAddr, err := udpconn.ReadFromUDP(buf)
		chkError(err)
		go clientHandle(buf, clientAddr, udpconn)
    }
}

func main() {
	middleware("127.0.0.1:53")
}