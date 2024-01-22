package detectors

import (
	"osint/pkg/request"
	"osint/pkg/structs"
	"osint/utils/logger"

	"github.com/tidwall/gjson"
)

type Gitlab struct{}

func (d Gitlab) Run(args structs.ScanArgs) (bool, string) {
	if len(args.UName) == 0 {
		return false, ""
	}
	// 判断用户名是否存在
	req := &request.Req{
		Schema:   "https",
		Endpoint: "gitlab.com",
		Path:     "/api/v4/users",
		Method:   "GET",
		Header:   make(map[string]string),
		Query:    "username=" + args.UName,
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("GitLab查询异常", err)
		return false, ""
	}

	body := request.ReadResponseBody(resp)
	info := gjson.Parse(body).Array()
	if len(info) > 0 {
		logger.Info(d.Desc())
		url := info[0].Get("web_url").String()
		logger.Warning(url)
		return true, url
	}
	logger.Error("GitLab未找到指定用户名")
	return false, ""
}

func (d Gitlab) Desc() string {
	return "GitLab存在指定用户名"
}

func init() {
	register("gitlab", Gitlab{})
}
