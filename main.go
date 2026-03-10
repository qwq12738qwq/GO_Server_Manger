package main

import (
	"fmt"
	"net/http"
	"os"

	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/sirupsen/logrus"
)

// 图片内存结构
type CacheItem struct {
	Data []byte
	Size int
}

// 划出图片内存
var (
	Cache      *lru.Cache[string, CacheItem]
	CacheBytes int
	CacheLock  sync.Mutex
)

var (
	Search_Location_IP_Memory    []byte
	Search_Location_IP_Memory_mu sync.RWMutex
)

var (
	Rules_Cache     = make([]Attack_Rules, 0, 100) // 内存数据
	Attack_Rules_mu sync.RWMutex                   // 读写锁
)

type Group_Attack_Struct struct {
	Attack_Level uint8
	Attack_Type  string
}

type Visitor_Datas struct {
	Total_Statistics_IP int
	Total_Visitor_IP    int
}

type IP_Response struct {
	Total_Normal_IP string
	Total_Attack_IP string
}

// 统计IP
// var Statistics_IP []string

func IPToRegion_Reading_Cache() {
	var dbPath string = "./ip2region_v4.xdb"
	var Error_Info string
	var err error
	Search_Location_IP_Memory, err = xdb.LoadContentFromFile(dbPath)
	if err != nil {
		fmt.Printf("failed to load content from `%s`: %s\n", dbPath, err)
		Error_Info = "查询IP地理数据库读取失败" + dbPath + "\n" + err.Error()
		Logger(Error_Info, "Error")
	}

}

// IP查询地理位置函数
func IPToRegion(ip string) string {
	var Info string
	searcher, err := xdb.NewWithBuffer(xdb.IPv4, Search_Location_IP_Memory)
	if err != nil {
		Info = "查询IP地理信息位置失败" + err.Error()
		Logger(Info, "Error")
		logrus.Panic(err)
	}
	region, err := searcher.SearchByStr(ip)
	if err != nil {
		Info = "查询IP地理位置失败" + err.Error()
		Logger(Info, "Error")
		logrus.Panic(err)
	}
	// 国外IP 澳大利亚|0|新南威尔士|悉尼|Cloudflare
	// 国内IP 中国|华东|上海|上海市|电信
	// 内网IP 0|0|0|内网IP|内网IP
	// 未知查询 0
	return region
}

// 日志函数
func Logger(Log_Info string, Error_level string) {
	logger := logrus.New() // 创建日志
	// 输出日志兼容Docker容器
	logFile, err := os.OpenFile("./run.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0664)
	if err != nil {
		logger.Fatal(err)
		// return "Error"
	}
	defer logFile.Close()

	// 输出到文件
	logger.SetOutput(logFile)
	// 保留时间戳
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	if Error_level == "Info" {
		logger.Info(Log_Info)
	}
	if Error_level == "Error" {
		logger.Error(Log_Info)
	}
	// return "Done"
}

func main() {
	// 创建内存
	Cache, _ = lru.New[string, CacheItem](50)
	// 每小时定时清理访问表数据
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			Clean_DB(Network_DB)
		}
	}()
	// 读取本地IP地理位置查询库
	Loding_Search_Local_IP := make(chan struct{})
	go func() {
		IPToRegion_Reading_Cache()
		close(Loding_Search_Local_IP)
	}()

	// 数据库连接堵塞
	Loding_DB_Connet := make(chan struct{})
	// 全局数据库连接
	go func() {
		Open_Local_DB()
		Open_Network_DB()
		close(Loding_DB_Connet)
		Logger("建立数据库连接成功", "Info")
	}()

	// 零内存堵塞
	Loding_DBMemory_Lock := make(chan struct{})
	// 数据库更新线程
	go func() {
		<-Loding_DB_Connet

		// 第一次执行
		time.Sleep(1 * time.Second)
		Rading_DB(Network_DB)
		Rading_Attacker_IP(Network_DB)
		close(Loding_DBMemory_Lock)

		time.Sleep(10 * time.Second)
		// 循环执行
		for {
			Rading_DB(Network_DB)
			Rading_Attacker_IP(Network_DB)
			time.Sleep(10 * time.Second)
		}
	}()

	// 更新内存规则线程
	go func() {
		<-Loding_DB_Connet
		for {
			//写入锁
			Attack_Rules_mu.Lock()
			Radding_Attack_Rules(Local_DB)
			Attack_Rules_mu.Unlock()
			time.Sleep(10 * time.Minute)
		}
	}()

	// API Server线程
	go func() {
		<-Loding_Search_Local_IP
		<-Loding_DBMemory_Lock
		// 创建API实例
		API_Server := mux.NewRouter()
		// 处理API请求
		API_Total_IP(API_Server)
		// 定义端口,启动服务
		error := http.ListenAndServe(":8088", API_Server)
		if error != nil {
			fmt.Println(error.Error())
		}
	}()

	<-Loding_DBMemory_Lock
	// 程序关闭时关闭数据库
	defer func() {
		Local_DB.Close()
		Network_DB.Close()
		os.Exit(0)
	}()
	// 堵塞主线程
	select {}
}
