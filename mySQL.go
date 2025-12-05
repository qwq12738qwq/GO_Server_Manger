package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

type Loging_Attacker struct {
	IP_Addr   string
	User_Name string
	Password  string
}

func Rading_Attacker_IP(db *sql.DB) {
	rows, err := db.Query("SELECT * FROM honeypot_login_logs")
	if err != nil {
		return
	}
	// 遍历表
	for rows.Next() {

	}

}
