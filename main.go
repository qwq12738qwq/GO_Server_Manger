package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type ConnetDB struct {
	DB_id   int
	DB_addr string
	// 数据库有定义默认值NULL
	DB_userAgent sql.NullString
	DB_visit_url sql.NullString

	VisitTime time.Time
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
var Statistics_IP []string

// 统计IP_API
func DataHandler(w http.ResponseWriter, r *http.Request) {
	// 请求头
	w.Header().Set("Content-Type", "application/json")
	// 请求数据库
	ip_info := connet_DB()
	// 构建Json
	resp := IP_Response{
		Total_Normal_IP: strconv.Itoa(ip_info[0]),
		Total_Attack_IP: strconv.Itoa(ip_info[1]),
	}
	//Json编码
	json.NewEncoder(w).Encode(resp)
}

// 定义路由
func API_Total_IP(API_Server *mux.Router) {
	API_Server.HandleFunc("/Visitors", DataHandler).Methods("GET")

}

// 日志函数
func Logger(Log_Info string, Error_level string) {
	logger := logrus.New() // 创建日志
	// 输出日志兼容Docker容器
	logFile, err := os.OpenFile("/app/run.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)
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

// 统计正常IP和攻击IP
func Statistics_IP_DB(visit_Cache []ConnetDB) []int {
	var group_IP = []int{0, 0}
	normal_IP := 0            // 正常IP
	attack_IP := 0            // 攻击IP
	seen := map[string]bool{} // 判断重复IP函数
	// db.Exec("DELETE FROM wp_visitor_logs WHERE ip_address = ?", "1.2.3.4") 删除某个IP所有记录
	for _, records := range visit_Cache {
		// 检测是否存在此值
		if records.DB_visit_url.Valid {
			// 判断是否为重复IP
			if seen[records.DB_addr] {
				continue // 跳过本次循环
			}
			seen[records.DB_addr] = true
			// 检测是否有Linux注入攻击 例子:";", "|", "||", "&&", "`", "$(", "<", ">", "%60", "${IFS}"
			if strings.Contains(records.DB_visit_url.String, "`") || strings.Contains(records.DB_visit_url.String, ";") {
				attack_IP++

				// 代理访问攻击(http/https)
			} else if strings.Contains(records.DB_visit_url.String, "/http://") || strings.Contains(records.DB_visit_url.String, "/https://") || strings.Contains(records.DB_visit_url.String, ":443") || strings.Contains(records.DB_visit_url.String, ":80") {
				attack_IP++

				// 数据库信息获取
			} else if strings.Contains(records.DB_visit_url.String, "/admin/.env.credentials") || strings.Contains(records.DB_visit_url.String, "/wp-admin/.env.credentials") || strings.Contains(records.DB_visit_url.String, "/config.js") || strings.Contains(records.DB_visit_url.String, "/keys.js") || strings.Contains(records.DB_visit_url.String, "/?author=") {
				attack_IP++

				// 获取管理者和注册用户
			} else if strings.Contains(records.DB_visit_url.String, "/wp-json/wp/v2/users") {
				attack_IP++
				// 检测攻击
			} else if strings.Contains(records.DB_visit_url.String, "cdn-cgi") || strings.Contains(records.DB_visit_url.String, "cloudflare") {
				attack_IP++
				// 检测登录面板
			} else if records.DB_visit_url.String == "https://loliconhentai.top/wp-admin" || records.DB_visit_url.String == "https://loliconhentai.top/wp-login.php" || records.DB_visit_url.String == "https://loliconhentai.top/admin" {
				attack_IP++
			} else {
				normal_IP++ // 记入正常IP
			}
		}
	}
	group_IP[0] = normal_IP
	group_IP[1] = attack_IP
	return group_IP
}

// 清理数据库
func Clean_DB(db *sql.DB) {
	// 数据库删除语法: DELETE FROM wp_visitor_logs WHERE visit_time < NOW() - INTERVAL 24 HOUR;
	// 删除24小时之前的数据,清理访问表
	db.Exec("DELETE FROM wp_visitor_logs WHERE visit_time < ? ", time.Now().Add(-24*time.Hour))
}

// // 获取时间戳
// func Timestamp_DB() time.Time {
// 	// 获取当前时间
// 	return time.Now().Add(-24 * time.Hour)
// }

// 连接数据库函数
func connet_DB() []int {

	// 容器内连接数据库
	db, error := sql.Open("mysql", ":@tcp()/?parseTime=true")
	if error != nil {
		println(error)
	}
	// 不关闭准备建立数据库,复用db函数
	//	defer db.Close() // 执行完函数才关闭
	fmt.Println("数据库连接成功！")
	// 查询数据库
	rows, err := db.Query("SELECT * FROM wp_visitor_logs WHERE visit_time >= ?", time.Now().Add(-24*time.Hour))
	if err != nil {
		println(error)
	}
	// 执行完函数关闭数据库连接,防止数据库连接过多爆炸
	defer rows.Close()
	// 定义slice,保证存储顺序一致
	visit_Cache := make([]ConnetDB, 0)
	Number := 1
	// Next--如果下一行有数据就true,反之flast
	for rows.Next() {

		var Data ConnetDB

		err := rows.Scan(
			&Data.DB_id,
			&Data.DB_addr,
			&Data.DB_userAgent,
			&Data.DB_visit_url,
			&Data.VisitTime,
		)
		// 判断是否有空值
		if err != nil {
			logrus.Fatal(err)

		}
		visit_Cache = append(visit_Cache, Data)
		Number++

	}
	Num := strconv.Itoa(Number) // 格式化字符串
	logrus.Info("已获取24小时的数据库数据" + Num + "条")
	Logger("已获取24小时的数据库数据"+Num+"条", "Info")
	// db.Exec("DELETE FROM wp_visitor_logs WHERE ip_address = ?", "1.2.3.4") 删除某个IP所有记录
	group_IP := Statistics_IP_DB(visit_Cache)
	Clean_DB(db)
	logrus.Info("访问IP个数" + strconv.Itoa(group_IP[0]) + "个")
	Logger("访问IP个数"+strconv.Itoa(group_IP[0])+"个", "Info")
	logrus.Info("识别出攻击IP个数" + strconv.Itoa(group_IP[1]) + "个")
	Logger("识别出攻击IP个数"+strconv.Itoa(group_IP[1])+"个", "Info")
	return group_IP
}

func main() {
	// Connet_DB()
	// 创建API实例
	API_Server := mux.NewRouter()
	// 处理API请求
	API_Total_IP(API_Server)
	// 定义端口,启动服务
	error := http.ListenAndServe(":8088", API_Server)
	if error != nil {
		fmt.Println(error.Error())
	}
}
