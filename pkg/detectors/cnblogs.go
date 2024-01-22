package detectors

import (
	"fmt"
	"osint/pkg/request"
	"osint/pkg/structs"
	"osint/utils/logger"
	"strings"
)

type CNblogs struct{}

func (d CNblogs) Run(args structs.ScanArgs) (bool, string) {
	if len(args.UName) == 0 {
		return false, ""
	}
	// 判断用户名是否存在
	req := &request.Req{
		Schema:   "https",
		Endpoint: "www.cnblogs.com",
		Path:     fmt.Sprintf("/%s", args.UName),
		Method:   "GET",
		Header:   make(map[string]string),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode == 404 {
		logger.Error("博客园未找到指定用户名")
		return false, ""
	}
	switch resp.StatusCode {
	case 200:
		logger.Info(d.Desc())
		logger.Warning(resp.Request.URL.String())
		return true, resp.Request.URL.String()
	case 301:
		u, err := resp.Location()
		if err != nil {
			return false, ""
		}

		msg := "博客园该用户名已变更为" + strings.TrimPrefix(u.Path, "/")
		logger.Warning(msg)
		return true, msg
	default:
		logger.Error("博客园未知状态码", resp.StatusCode)
	}
	return false, ""
}

func (d CNblogs) Desc() string {
	return "博客园存在指定用户名"
}

func init() {
	register("cnblogs", CNblogs{})
}
