/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"bytes"
	"net/http"
	"fmt"
	"log"
	"strings"
	"time"
	"encoding/json"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)
//日志的结构体
type PacketLog struct{
	Time string `json:"time"`
	WorkerID int `json:"worker_id"`
	Protocol  string `json:"protocol"` // "HTTP" 或 "DNS"
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   string `json:"src_port,omitempty"` // omitempty 表示如果是空就不显示
	DstPort   string `json:"dst_port,omitempty"`
	Detail    string `json:"detail"` // 摘要内容
	Payload   string `json:"payload,omitempty"` // 完整数据(选填)
}
//全局变量
var (
	iface string
	workers int
	logFile *os.File //日志文件句柄
	fileMu sync.Mutex//文件写入锁
)
//发送给java后端
func sendToBackend(payload string){
	url:="http://localhost:8080/api/upload"
	reqBody:=bytes.NewBuffer([]byte(payload))
	resp,err:=http.Post(url,"text/plain",reqBody)
	if err!=nil{
		fmt.Printf("发送后端失败：%v\n",err)
		return
	}
	defer resp.Body.Close()
}
//写日志
func writeLog(entry PacketLog){
	jsonData,err:=json.Marshal(entry)
	if err !=nil{
		log.Printf("JSON序列化失败：%v",err)
		return
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	if logFile!=nil{
		logFile.Write(jsonData)
		logFile.WriteString("\n")
	}
	fmt.Printf("[Worker %d] 已记录%s流量->%s\n",entry.WorkerID,entry.Protocol,"traffic.log")

}
//从管道获取数据进行处理
func worker(id int,jobs <-chan gopacket.Packet){
	for packet := range jobs{
		timestamp:=packet.Metadata().Timestamp.Format("2006-01-02 15:04:05")
		//处理udp数据
		udplayer:=packet.Layer(layers.LayerTypeUDP)
		if udplayer!=nil{
			udp,_:=udplayer.(*layers.UDP)
			//流量过滤，筛选53端口dns服务的流量
			if udp.SrcPort==53||udp.DstPort==53{
				logEntry:=PacketLog{
					Time:timestamp,
					WorkerID:id,
					Protocol:"DNS",
					SrcPort:  fmt.Sprintf("%d", udp.SrcPort),
					DstPort:  fmt.Sprintf("%d", udp.DstPort),
					Detail:   fmt.Sprintf("Length: %d bytes", len(udp.Payload)),
				}
				// fmt.Printf("[Worker %d] [UDP/DNS] 发现 DNS 流量 [%s]\n", id, packet.Metadata().Timestamp.Format("15:04:05"))
				//解析ip信息
				ipLayer:=packet.Layer(layers.LayerTypeIPv4)
				if ipLayer!=nil{
					ip,_:=ipLayer.(*layers.IPv4)
					logEntry.SrcIP = ip.SrcIP.String()
					logEntry.DstIP = ip.DstIP.String()
					// fmt.Printf("来源：%s:%d  ->目标：%s:%d",ip.SrcIP,udp.SrcPort,ip.DstIP,udp.DstPort)
				}
				writeLog(logEntry)
				// fmt.Printf("数据包长度：%d bytes（DNS查询/响应）",len(udp.Payload))
				// fmt.Printf("------------------------------")
			}
		}
		//截取HTTP数据并处理
			//ApplicationLayer()获取最后一层数据，HTTP在最后一层，如果是其它协议的话是乱码。通过后续的判断进行过滤
			appLayer := packet.ApplicationLayer()
			if appLayer != nil {
				//获取payload，此时为二进制数据
				payload := appLayer.Payload()
				if len(payload) > 0 {
					content := string(payload)
					//判断是否是HTTP
					if strings.Contains(content,"GET /") || strings.Contains(content,"POST /") || strings.Contains(content,"HTTP/1.1"){
						logEntry:=PacketLog{
							Time:timestamp,
							WorkerID:id,
							Protocol:"HTTP",
							Detail:   "",
						}
						if len(content)>100{
							logEntry.Detail=content[:100]+"..."
						}else{
							logEntry.Detail=content
						}
						
						// fmt.Printf("[Worker %d]>>>发现HTTP痕迹 [%s]\n",id,packet.Metadata().Timestamp.Format("15:04:05"))

						//解析ip信息
						ipLayer := packet.Layer(layers.LayerTypeIPv4)
						if ipLayer != nil {
							ip,_ := ipLayer.(*layers.IPv4)
							logEntry.SrcIP = ip.SrcIP.String()
							logEntry.DstIP = ip.DstIP.String()
							// fmt.Printf("来源：%s ->目标：%s \n",ip.SrcIP,ip.DstIP)
						}
						
						writeLog(logEntry)
						//打印200个字符验证
						// displayLen := 200
						// if len(content) < displayLen {
						// 	displayLen=len(content)
						// }
						// fmt.Printf("内容摘要：%s \n",content[:displayLen])
						// fmt.Printf("--------------------------------------------")
						sendToBackend(content)
					}
				}
			}
	}
}	
// sniffCmd represents the sniff command
var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "抓取并解析网络包",
	Long: `监听指定网卡，解析IPV4和TCP/UDP协议数据`,
	Run: func(cmd *cobra.Command, args []string) {
		//创建日志文件
		var err error
		logFile,err=os.OpenFile("traffic.log",os.O_APPEND|os.O_CREATE|os.O_WRONLY,0644)
		if err!=nil{
			log.Fatal("无法打开日志文件",err)
		}
		defer logFile.Close()

		//1.配置阶段
		deviceName := "ens33"
		snapLen := int32(65535)  //监听的网络包的长度
		promisc := false  //混杂模式
		timeout := 30 * time.Second

		//2.打开设备
		handle, err := pcap.OpenLive(deviceName,snapLen,promisc,timeout)//打开网卡，拿到原始字节流
		if err != nil{
			log.Fatal("打开网卡失败：",err)
		}
		defer handle.Close()
		fmt.Printf("开始在%s上抓包...\n", deviceName)

		//3.设置过滤器
		err = handle.SetBPFFilter("tcp or udp")
		if err != nil {
			log.Fatal("设置过滤器失败：",err)
		}

		//4.创建数据流
		packetSource := gopacket.NewPacketSource(handle,handle.LinkType())//处理字节流，解析，整理

		jobs:=make(chan gopacket.Packet,1000)
		for w:=1;w<=workers;w++{
			go worker(w,jobs)
			fmt.Printf("启动worker %d ...\n",w)
		}

		//5.循环处理包
		for packet := range packetSource.Packets() {
			jobs <- packet
			// //获取IP层
			// ipLayer := packet.Layer(layers.LayerTypeIPv4)
			// if ipLayer != nil {
			// 	ip,_ := ipLayer.(*layers.IPv4)
			// 	fmt.Printf("[IP] %s -> %s",ip.SrcIP,ip.DstIP)
			// }
			// //获取TCP层
			// tcpLayer := packet.Layer(layers.LayerTypeTCP)
			// if tcpLayer != nil {
			// 	tcp,_ := tcpLayer.(*layers.TCP)
			// 	fmt.Printf("[TCP Port] %d -> %d",tcp.SrcPort,tcp.DstPort)
			// }

			// fmt.Printf("\n")

			
		}

	},
}

func init() {
	rootCmd.AddCommand(sniffCmd)

	sniffCmd.Flags().StringVarP(&iface,"iface","i","ens33","指定要监听的网卡")
	sniffCmd.Flags().IntVarP(&workers,"workers","w",5,"指定工作协程的数量")
}
