// filesrv —— 本地集成测试负载服务器：任何路径返回固定标记内容。
// 用法: filesrv <port>
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: filesrv <port>")
		os.Exit(2)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ghostpipe-e2e-ok via %s", r.Host)
	})
	if err := http.ListenAndServe("127.0.0.1:"+os.Args[1], nil); err != nil {
		fmt.Fprintln(os.Stderr, "filesrv 退出:", err)
		os.Exit(1)
	}
}
