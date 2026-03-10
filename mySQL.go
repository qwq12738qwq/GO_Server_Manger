package main

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

type Password_Attack_Login struct {
	Attack_IP   string
	Username    sql.NullString
	Password    sql.NullString
	Attack_Time time.Time
}

type ConnetDB struct {
	DB_id   int
	DB_addr string
	// 数据库有定义默认值NULL
	DB_userAgent sql.NullString
	DB_visit_url sql.NullString

	VisitTime time.Time
}

type Attack_Rules struct {
	Attack_type string
	Match_type  uint8
	Pattern     string
}

type Loging_Attacker struct {
	IP_Addr   string
	User_Name string
	Password  string
}

var (
	Local_DB   *sql.DB
	Network_DB *sql.DB
)

var (
	Visit_Cache    = make([]ConnetDB, 0, 1000)
	Visit_Cache_mu sync.RWMutex
)
var (
	Password_Attack_Login_Group    = make([]Password_Attack_Login, 0, 500)
	Password_Attack_Login_Group_mu sync.RWMutex
)

func Open_Local_DB() {
	var err error // 声明
	Local_DB, err = sql.Open("sqlite3", "./database.db")
	if err != nil {
		logrus.Panic(err)
	}
	// 给GC回收
	err = nil

}

func Open_Network_DB() {
	var err error // 声明
	Network_DB, err = sql.Open("mysql", "THNEden:HUANGLIANGJIE.30@tcp(mariadb)/wordpress?parseTime=true")
	if err != nil {
		logrus.Panic(nil)
	}
	err = nil
}

func Wiring_Attack_Info_To_DB(use_Local_DB *sql.DB, attack_info map[string][]Group_Attack_Struct) {
	// 读取锁
	Search_Location_IP_Memory_mu.RLock()
	defer Search_Location_IP_Memory_mu.RUnlock()

	stmt, err := use_Local_DB.Prepare("INSERT INTO attack_ip (IP_Addr, Attack_Mode, Location) VALUES (?, ?, ?)")
	if err != nil {
		logrus.Panic(err)
	}
	for ip_addr, group_ip_info := range attack_info {
		for _, info := range group_ip_info {
			_, err = stmt.Exec(ip_addr, info.Attack_Type, IPToRegion(ip_addr))
			if err != nil {
				logrus.Panic(err)
			}
		}
	}
}

func Rading_Attacker_IP(use_Network_DB *sql.DB) {
	Password_Attack_Login_Group = Password_Attack_Login_Group[:0]
	rows, err := use_Network_DB.Query("SELECT ip,username,password,visit_time FROM honeypot_login_logs")
	if err != nil {
		logrus.Panic(err)
	}
	Password_Attack_Login_Group_mu.Lock()
	// 遍历表
	for rows.Next() {
		var data Password_Attack_Login
		rows.Scan(
			&data.Attack_IP,
			&data.Username,
			&data.Password,
			&data.Attack_Time,
		)
		Password_Attack_Login_Group = append(Password_Attack_Login_Group, data)
	}
	Password_Attack_Login_Group_mu.Unlock()
}

// 读取本地数据库攻击判定规则
func Radding_Attack_Rules(use_Local_DB *sql.DB) []Attack_Rules {
	// 清理数组,防止占用内存无限扩张
	Rules_Cache = Rules_Cache[:0]

	rows, err := use_Local_DB.Query("SELECT attack_type,match_type,pattern FROM attack_rules")
	if err != nil {
		logrus.Panic(err)
	}
	for rows.Next() {
		var datas Attack_Rules
		rows.Scan(
			&datas.Attack_type,
			&datas.Match_type,
			&datas.Pattern,
		)
		Rules_Cache = append(Rules_Cache, datas)
	}
	return Rules_Cache
}

// 连接网络数据库函数
func Rading_DB(use_Network_DB *sql.DB) {
	// 清空内存
	Visit_Cache = Visit_Cache[:0]

	// 查询数据库
	rows, err := use_Network_DB.Query("SELECT * FROM wp_visitor_logs WHERE visit_time >= ?", time.Now().Add(-24*time.Hour))
	if err != nil {
		logrus.Panic(err)
	}
	Number := 1

	Visit_Cache_mu.Lock()
	// Next--如果下一行有数据就true,反之flast
	for rows.Next() {
		var Data ConnetDB
		rows.Scan(
			&Data.DB_id,
			&Data.DB_addr,
			&Data.DB_userAgent,
			&Data.DB_visit_url,
			&Data.VisitTime,
		)

		Visit_Cache = append(Visit_Cache, Data)
		Number++

	}

	Visit_Cache_mu.Unlock()

	// Num := strconv.Itoa(Number) // 格式化字符串
	// logrus.Info("已获取24小时的数据库数据" + Num + "条")
	// Logger("已获取24小时的数据库数据"+Num+"条", "Info")
	// db.Exec("DELETE FROM wp_visitor_logs WHERE ip_address = ?", "1.2.3.4") 删除某个IP所有记录
	// group_IP, attack_map := Statistics_IP_DB()
	// logrus.Info("访问IP个数" + strconv.Itoa(group_IP[0]) + "个")
	// Logger("访问IP个数"+strconv.Itoa(group_IP[0])+"个", "Info")
	// logrus.Info("识别出攻击IP个数" + strconv.Itoa(group_IP[1]) + "个")
	// Logger("识别出攻击IP个数"+strconv.Itoa(group_IP[1])+"个", "Info")
	// return group_IP, attack_map
}

// 读取数据库关键词
func Rading_keyword_group(use_Local_DB *sql.DB) map[string]KeywordGroupItem {
	rows, err := use_Local_DB.Query(`SELECT name, delay FROM keywords`)
	if err != nil {
		logrus.Panic(err)
	}
	result := make(map[string]KeywordGroupItem)
	for rows.Next() {
		var name string
		var delay int
		rows.Scan(&name, &delay)

		result[name] = KeywordGroupItem{
			Delay: delay,
		}
	}
	return result
}

func Rading_keyword_Knowledge(use_Local_DB *sql.DB, keyword string) (*KeywordDetail, error) {
	if keyword == "" {
		return nil, errors.New("empty keyword")
	} else {
		row := use_Local_DB.QueryRow(`
		SELECT title, content, delay, button_text, button_link
		FROM keywords
		WHERE name = ?
		`, keyword)
		var detail KeywordDetail
		err := row.Scan(&detail.Title, &detail.Content, &detail.Delay, &detail.Button_text, &detail.Button_link)
		if err != nil {
			if err == sql.ErrNoRows {
				logrus.WithField("keyword", keyword).Warn("keyword not found in database")
			} else {
				logrus.WithError(err).Error("database scan failed")
			}
			return nil, err
		}

		logrus.WithField("keyword", keyword).Info("keyword knowledge loaded")
		return &detail, nil
	}

}

// 清理数据库
func Clean_DB(use_Network_DB *sql.DB) {
	// 数据库删除语法: DELETE FROM wp_visitor_logs WHERE visit_time < NOW() - INTERVAL 24 HOUR;
	// 删除24小时之前的数据,清理访问表
	use_Network_DB.Exec("DELETE FROM wp_visitor_logs WHERE visit_time < ? ", time.Now().Add(-24*time.Hour))
}

// // 获取时间戳
// func Timestamp_DB() time.Time {
// 	// 获取当前时间
// 	return time.Now().Add(-24 * time.Hour)
// }

// 统计正常IP和攻击IP
func Statistics_IP_DB() ([]int, map[string][]Group_Attack_Struct) {
	group_attack := make(map[string][]Group_Attack_Struct)
	var group_IP = []int{0, 0}
	var normal_IP int = 0 // 正常IP
	// attack_IP := 0            // 攻击IP
	seen := map[string]bool{} // 判断重复IP Map
	// db.Exec("DELETE FROM wp_visitor_logs WHERE ip_address = ?", "1.2.3.4") 删除某个IP所有记录
	// all_total_IP := len(visit_Cache)

	// 读取锁
	Password_Attack_Login_Group_mu.RLock()
	Attack_Rules_mu.RLock()
	Visit_Cache_mu.RLock()

	defer Password_Attack_Login_Group_mu.RUnlock()
	defer Attack_Rules_mu.RUnlock()
	defer Visit_Cache_mu.RUnlock()

	for _, records := range Visit_Cache {
		var distinguish uint8 = 0
		// 检测是否存在此值
		if records.DB_visit_url.Valid {
			for _, rules_cache := range Rules_Cache {
				// 判断攻击IP
				if strings.Contains(records.DB_visit_url.String, rules_cache.Pattern) {
					group_attack[records.DB_addr] = append(group_attack[records.DB_addr], Group_Attack_Struct{Attack_Level: rules_cache.Match_type, Attack_Type: rules_cache.Attack_type})
					distinguish++
					// 优化性能
					continue
				}
			}
			// 正常IP统计
			if !seen[records.DB_addr] && distinguish == 0 {
				seen[records.DB_addr] = true
				normal_IP++
			}
		}
	}
	// 统计攻击撞库IP

	// 写入数据库线程
	// go func() {
	// 	Wiring_Attack_Info_To_DB(Local_DB, group_attack)
	// }()

	group_IP[0] = normal_IP
	group_IP[1] = len(group_attack)
	return group_IP, group_attack
}
