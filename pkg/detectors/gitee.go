package detectors

import (
	"fmt"
	"osint/pkg/request"
	"osint/pkg/schema"
	"osint/utils/logger"
)

type Gitee struct{}

func (d Gitee) Run(options schema.Options) (bool, string) {
	username, ok := options.GetMetadata("Username")
	if !ok {
		return false, ""
	}
	// 判断用户名是否存在
	req := &request.Req{
		Schema:   "https",
		Endpoint: "gitee.com",
		Path:     fmt.Sprintf("/%s", username),
		Method:   "GET",
		Header:   make(map[string]string),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode == 404 {
		logger.Error("Gitee未找到指定用户名")
		return false, ""
	}

	switch resp.StatusCode {
	case 200:
		logger.Info(d.Desc())
		logger.Warning(resp.Request.URL.String())
		return true, resp.Request.URL.String()
	default:
		logger.Error("Gitee未知状态码", resp.StatusCode)
	}
	return false, ""
}

func (d Gitee) Desc() string {
	return "Gitee存在指定用户名"
}

func init() {
	register("gitee", Gitee{})
}
