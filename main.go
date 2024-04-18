package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"log"

	"github.com/chai2010/winsvc"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows/svc/mgr"
)

// Define your WireGuard service name prefix
const servicePrefix = "WireGuardTunnel"

// Define your DNS server address
const dnsServer = "114.114.114.114:53"

// Define your domain name to monitor
var domain string
var tunnelname string

var oldIps []string

var logger *log.Logger

func init() {
	// 创建或打开日志文件
	file, err := os.OpenFile("C:\\wireguardWatcher.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("无法打开日志文件:", err)
	}
	// 设置日志输出到文件
	logger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	config := InitConfig("C:\\wireguardwatcher.conf")
	domain = config["domain"]
	tunnelname = config["tunnelname"]
	fmt.Println("domain=", string(domain), " tunnelname=", string(tunnelname))

	// // Create a new service manager
	// m, err := mgr.Connect()
	// if err != nil {
	// 	fmt.Println("Error connecting to service manager:", err)
	// 	return
	// }
	// defer m.Disconnect()

	srvConfig := &service.Config{
		Name:        "WireguardWatcherService",
		DisplayName: "Wireguard监视",
		Description: "监控wireguard域名记录变化，自动重启服务",
	}
	prg := &program{}
	s, err := service.New(prg, srvConfig)
	if err != nil {
		fmt.Println(err)
	}
	if len(os.Args) > 1 {
		serviceAction := os.Args[1]
		switch serviceAction {
		case "install":
			err := s.Install()
			if err != nil {
				fmt.Println("安装服务失败: ", err.Error())
				logger.Println("service install fail")
			} else {
				fmt.Println("安装服务成功")
				logger.Println("service install success")
			}
			return
		case "uninstall":
			err := s.Uninstall()
			if err != nil {
				fmt.Println("卸载服务失败: ", err.Error())
				logger.Println("uninstall install fail")
			} else {
				fmt.Println("卸载服务成功")
				logger.Println("uninstall install success")
			}
			return
		case "start":
			err := s.Start()
			if err != nil {
				fmt.Println("运行服务失败: ", err.Error())
				logger.Println("run service fail")
			} else {
				fmt.Println("运行服务成功")
				logger.Println("run service success")
			}
			return
		case "stop":
			err := s.Stop()
			if err != nil {
				fmt.Println("停止服务失败: ", err.Error())
				logger.Println("stop service fail")
			} else {
				logger.Println("stop service success")
			}
			return
		}
	}

	err = s.Run()
	if err != nil {
		fmt.Println(err)
	}
}

// Define the program struct
type program struct{}

// Run method is the main service logic
func (p *program) run() {
	// Create a new DNS client
	client := new(dns.Client)

	// Define a channel to signal service restart
	restart := make(chan struct{})

	go restartService(restart)

	// Start an infinite loop to monitor DNS A record changes
	for {
		if domain != "" && tunnelname != "" {
			// Resolve A records for the domain
			msg := new(dns.Msg)
			msg.SetQuestion(domain+".", dns.TypeA)
			resp, _, err := client.Exchange(msg, dnsServer)
			if err != nil {
				fmt.Println("Error resolving DNS:", err)
				logger.Println("Error resolving DNS", err)
				continue
			}

			// Check if A records have changed
			newIPs := make([]string, len(resp.Answer))
			for i, answer := range resp.Answer {
				if a, ok := answer.(*dns.A); ok {
					newIPs[i] = a.A.String()
				}
			}

			if len(oldIps) == 0 {
				fmt.Println("first loop?")
				logger.Println("first loop?")
			} else {
				// Check if A records have changed
				if !ipsEqual(oldIps, newIPs) {
					// A records have changed, trigger service restart
					fmt.Println("A records have changed. Restarting WireGuard services...")
					logger.Println("A records have changed. Restarting WireGuard services.newIP:", newIPs)
					restart <- struct{}{}
				} else {
					fmt.Println("A records not changed.")
					logger.Println("A records not changed.", oldIps)
				}
			}
			oldIps = newIPs

		} else {
			logger.Println("请确保配置文件正确")
		}
		// Wait for some time before checking again
		time.Sleep(30 * time.Second)
	}
}

// ipsEqual checks if two slices of IP addresses are equal
func ipsEqual(ips1, ips2 []string) bool {
	if len(ips1) != len(ips2) {
		fmt.Println(ips1, ips2)
		return false
	}
	for i := range ips1 {
		if ips1[i] != ips2[i] {
			return false
		}
	}
	fmt.Println(ips1, ips2)
	return true
}

func restartService(restart chan struct{}) {

	for {
		<-restart
		//fmt.Println(sig)
		// You can call a function to restart the service or directly place the logic here
		fmt.Println("Received restart signal. Restarting service...")
		logger.Println("Received restart signal. Restarting service...")
		// Create a new service manager
		m, err := mgr.Connect()
		if err != nil {
			fmt.Println("Error connecting to service manager:", err)
		}
		defer m.Disconnect()

		// List services
		services, err := m.ListServices()
		if err != nil {
			fmt.Println("Error listing services:", err)

		}
		// Filter services with specified prefix
		for _, ser := range services {
			//fmt.Println(svc)
			if strings.HasPrefix(ser, servicePrefix) {
				fmt.Println(ser)
				if strings.Contains(ser, tunnelname) {
					fmt.Println("restarting target", ser)
					sta, _ := winsvc.QueryService(ser)
					fmt.Println("winsvc query:", sta)
					winsvc.StopService(ser)
					time.Sleep(5 * time.Second)
					winsvc.StartService(ser)
				}

			}
		}
		m.Disconnect()
		// Perform restart operation
	}

}

// 读取key=value类型的配置文件
func InitConfig(path string) map[string]string {
	config := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		s := strings.TrimSpace(string(b))
		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}
		key := strings.TrimSpace(s[:index])
		if len(key) == 0 {
			continue
		}
		value := strings.TrimSpace(s[index+1:])
		if len(value) == 0 {
			continue
		}
		config[key] = value
	}
	return config
}

func (p *program) Start(s service.Service) error {
	fmt.Println("服务运行...")
	logger.Println("开始运行服务...")
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	return nil
}
