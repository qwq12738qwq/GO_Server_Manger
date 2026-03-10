package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type KeywordGroupItem struct {
	Delay int `json:"delay"`
}

type KeywordDetail struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Delay   int    `json:"delay"`
	// 识别出按钮为空,而不是空字符串
	Button_text *string `json:"button_text"`
	Button_link *string `json:"button_link"`
}

// 统计IP_API
func DataHandler(w http.ResponseWriter, r *http.Request) {
	// 请求头
	w.Header().Set("Content-Type", "application/json")
	// 请求数据
	ip_info, _ := Statistics_IP_DB()
	// 构建Json
	resp := IP_Response{
		Total_Normal_IP: strconv.Itoa(ip_info[0]),
		Total_Attack_IP: strconv.Itoa(ip_info[1]),
	}
	//Json编码
	json.NewEncoder(w).Encode(resp)
}

// 详细攻击统计API
func Data_Attack_Info(w http.ResponseWriter, r *http.Request) {
	// 请求头
	w.Header().Set("Content-Type", "application/json")
	// 测试数据

	_, Attack_Info := Statistics_IP_DB()
	json.NewEncoder(w).Encode(Attack_Info)

}

// 关键词请求API
func Keyword_Group(w http.ResponseWriter, r *http.Request) {
	// 请求头
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Rading_keyword_group(Local_DB))
}

func Keyword_Knowledge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	name := r.URL.Query().Get("name")
	if name == "" {
		logrus.Warn("Keyword_Knowledge: missing query param 'name'")
		http.Error(w, "missing name parameter", http.StatusBadRequest)
		return
	}

	detail, err := Rading_keyword_Knowledge(Local_DB, name)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"keyword": name,
			"error":   err,
		}).Error("failed to read keyword knowledge")

		http.Error(w, "keyword not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(detail)
}

// 定义路由
func API_Total_IP(API_Server *mux.Router) {
	API_Server.HandleFunc("/Visitors", DataHandler).Methods("GET")                                      // 简单统计IP
	API_Server.HandleFunc("/AttckInfo", Data_Attack_Info).Methods("GET")                                // 攻击IP更详细信息
	API_Server.HandleFunc("/infoapi/group", Keyword_Group).Methods("GET")                               // 关键词获取
	API_Server.HandleFunc("/infoapi/keyword", Keyword_Knowledge).Methods("GET")                         // 获取关键词信息
	API_Server.HandleFunc("/wp-content/uploads/{path:.*}", Reading_image)                               // 图片&静态文件接口
	API_Server.HandleFunc("/wp-content/themes/lolimeow-lolimeowV13.13/assets/{path:.*}", Reading_image) // 图片文件第二路径
	API_Server.HandleFunc("/update", Change_Update_HTML)                                                // 更新界面
}
