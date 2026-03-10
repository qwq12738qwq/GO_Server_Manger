package main

import (
	"database/sql"
	"html/template"
	"net/http"
	"time"
)

type wp_Update_Information_Struct struct {
	Version     string
	Title       string
	Author      string
	Content     string
	Update_Time time.Time
}

type UpdateMessage struct {
	Little_title string // 对应模板里的 {{.little_title}}
	Info         string // 对应模板里的 {{.Info}}
}

type Update_Title struct {
	Date           string          // {{.Date}}
	Version        string          // {{.Version}}
	Updater        string          // {{.Updater}}
	Title          string          // {{.title}}
	Update_Message []UpdateMessage // {{range.Update_Message}}
}

// 存储数据地址
type PageData struct {
	UpdateTitle []*Update_Title // {{range .Update_Title}}
}

func Reading_DB_UpDatas(use_Local_DB *sql.DB) {
	var update PageData
	rows, err := use_Local_DB.Query("SELECT Date,Version,Author,Title,Content FROM wp_visitor_logs")
	if err != nil {
		Logger("查询本地数据--更新日志失败", "Error")
		return
	}
	for rows.Next() {
		var data Update_Title
		err := rows.Scan(
			&data.Date,
			&data.Version,
			&data.Updater,
			&data.Title,
			&data.Update_Message,
		)
		if err != nil {
			Logger("查询表--存储更新日志到内存失败", "Error")
		}
		update.UpdateTitle = append(update.UpdateTitle, &data)
	}
}
func Change_Update_HTML(w http.ResponseWriter, r *http.Request) {
	var wp_Update_Information wp_Update_Information_Struct
	html, _ := template.ParseFiles("templates/index_update.html")
	html.Execute(w, wp_Update_Information)

}
