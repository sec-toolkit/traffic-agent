/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

// sniffCmd represents the sniff command
var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "抓取并解析网络包",
	Long: `监听指定网卡，解析IPV4和TCP/UDP协议数据`,
	Run: func(cmd *cobra.Command, args []string) {
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
		err = handle.SetBPFFilter("tcp")
		if err != nil {
			log.Fatal("设置过滤器失败：",err)
		}

		//4.创建数据流
		packetSource := gopacket.NewPacketSource(handle,handle.LinkType())//处理字节流，解析，整理

		//5.循环处理包
		for packet := range packetSource.Packets() {
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
						fmt.Printf(">>>发现HTTP痕迹 [%s]\n",packet.Metadata().Timestamp.Format("15:04:05"))

						//解析ip信息
						ipLayer := packet.Layer(layers.LayerTypeIPv4)
						if ipLayer != nil {
							ip,_ := ipLayer.(*layers.IPv4)
							fmt.Printf("来源：%s ->目标：%s \n",ip.SrcIP,ip.DstIP)
						}
						
						//打印200个字符验证
						displayLen := 200
						if len(content) < displayLen {
							displayLen=len(content)
						}
						fmt.Printf("内容摘要：%s \n",content[:displayLen])
						fmt.Printf("--------------------------------------------")
					}
				}
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(sniffCmd)

}
