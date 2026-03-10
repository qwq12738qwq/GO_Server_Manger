package main

import (
	"bytes"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/chai2010/webp"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// 禁止访问特定目录列表
var ban_Dirs = []string{
	"js/",
	"css/",
	"custom-css-js",
	"ao_ccss",
}

func Reading_image(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	relPath := vars["path"]
	var fullPath string
	// 防止 .. 遍历目录
	if strings.Contains(relPath, "..") {
		http.Error(w, "directory not accessible", http.StatusInternalServerError)
		//	res_404Image(w)
		return
	}

	// 禁止访问特定路径
	for _, dir := range ban_Dirs {
		if strings.Contains(relPath, dir) {
			http.Error(w, "directory not accessible", http.StatusInternalServerError)
			return
		}
	}

	// 拼接路径(适应Docker环境)
	if strings.Contains(relPath, "images/") {
		fullPath = filepath.Join("/app/wp-content/themes/lolimeow-lolimeowV13.13/assets", relPath)
		Logger(fullPath, "Info")
	} else {
		fullPath = filepath.Join("/app/wp-content/uploads", relPath)
		Logger(fullPath, "Info")
	}

	// 检测目录
	info, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "directory not accessible", http.StatusInternalServerError)
		return
	}

	//阻止目录访问
	if info.IsDir() {
		http.Error(w, "directory not accessible", http.StatusInternalServerError)
		return
	}

	// 除开图片之外的文件(例如css/js)直接传输
	if Return_Format(fullPath) == "application/octet-stream" {
		// 转小写
		ext := strings.ToLower(filepath.Ext(fullPath))
		//打开文件
		Logger("不是图片,不进行转码", "Info")
		file, err := os.Open(fullPath)
		if err != nil {
			Logger("无法打开文件,文件不存在(NotFound_Image)", "Error")
			http.NotFound(w, r)
			return
		}
		defer file.Close()

		// 获取文件信息
		info, _ := file.Stat()

		w.Header().Set("Content-Type", mime.TypeByExtension(ext))
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
		return
	}
	// 先检测路径是否存在
	// if _, err := os.Stat(fullPath); err != nil {
	// 	http.Error(w, "Uploads directory not accessible", http.StatusInternalServerError)
	// 	return
	// }
	// 防止和本地文件冲突
	cacheKey := relPath + "|webp"
	Http_Format := Return_Format(r.Header.Get("Accept"))
	// 先处理内存中的图片
	if Http_Format == "image/webp" {
		if data, ok_bool := getCache(cacheKey); ok_bool {
			w.Header().Set("Content-Type", Http_Format)
			w.Write(data)
			return
		}
	}

	img_file, err := os.Open(fullPath)
	if err != nil {
		logrus.Println("Go received:", r.URL.Path)
		http.Error(w, "directory not accessible", http.StatusInternalServerError)
		Logger(err.Error(), "Info")
		return
	}
	defer img_file.Close()

	// 解码图片文件
	img, format_Image, err := image.Decode(img_file)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// WebP 转码
	if strings.Contains(r.Header.Get("Accept"), "image/webp") && (format_Image == "jpeg" || format_Image == "png") {
		// 缓冲区
		var buf bytes.Buffer
		webp.Encode(&buf, img, &webp.Options{Quality: 80})

		data := buf.Bytes()
		addCache(cacheKey, data)

		w.Header().Set("Content-Type", "image/webp")
		w.Write(data)
		return
	}

	// 获取图片信息
	fileInfo, err := img_file.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 重置文件指针
	img_file.Seek(0, 0)
	http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), img_file)
}

// 判断格式函数
func Return_Format(format string) string {
	switch true {
	case strings.Contains(format, ".jpg"):
		return "image/jpeg"
	case strings.Contains(format, ".jpeg"):
		return "image/jpeg"
	case strings.Contains(format, ".pxng"):
		return "image/png"
	case strings.Contains(format, ".gif"):
		return "image/gif"
	case strings.Contains(format, ".webp"):
		return "image/webp"
	case strings.Contains(format, ".bmp"):
		return "image/bmp"
	case strings.Contains(format, ".ico"):
		return "image/x-icon"
	case strings.Contains(format, ".svg"):
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

// 读取内存(字节控制)
func getCache(key string) ([]byte, bool) {
	CacheLock.Lock()
	defer CacheLock.Unlock()

	item, ok := Cache.Get(key)
	if !ok {
		return nil, false
	}
	return item.Data, true
}

// 写入内存(图片超过5MB排除在外)
func addCache(key string, data []byte) {
	CacheLock.Lock()
	defer CacheLock.Unlock()

	size := len(data)

	// 图片缓存大于100M
	for CacheBytes+size > 100*1024*1024 {
		k, v, ok := Cache.RemoveOldest()
		if !ok {
			break
		}
		CacheBytes -= v.Size
		_ = k
	}

	Cache.Add(key, CacheItem{
		Data: data,
		Size: size,
	})
	CacheBytes += size
}

// func res_404Image (w http.ResponseWriter){
// 	w.WriteHeader(http.StatusNotFound)
// }
