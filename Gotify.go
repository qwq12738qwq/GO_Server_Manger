package main

import (
	"net/http"
)

type Http_Hader struct {
	Token       string
	ContentType string
}

type Post_Datas struct {
	Message  string
	Priority uint8
	Title    string
}

var http_Url string = ""

// var contentType string = "application/json"

func Post_Gotify_Message() {
	Hader := Http_Hader{
		Token:       "",
		ContentType: "applocation/json",
	}
	req, err := http.Request("POST", http_Url, "")
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", Hader.ContentType)
}
