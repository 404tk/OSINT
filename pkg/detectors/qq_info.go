package detectors

import (
	"fmt"
	"osint/pkg/request"
	"osint/pkg/schema"
	"osint/utils/logger"

	"github.com/tidwall/gjson"
)

type QQInfo struct{}

func (d QQInfo) Run(options schema.Options) (bool, string) {
	qq, ok := options.GetMetadata("QQ")
	if !ok {
		return false, ""
	}

	req := &request.Req{
		Schema:   "https",
		Endpoint: "qagzs.com:88",
		Path:     "/api/qq昵称/",
		Method:   "GET",
		Header:   make(map[string]string),
		Query:    fmt.Sprintf("qq=%s", qq),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("QQ昵称查询接口异常", err)
		return false, ""
	}

	logger.Info(d.Desc())

	body := request.ReadResponseBody(resp)
	name := gjson.Get(body, "name").String()
	if name != "" {
		msg := "QQ昵称: " + name
		logger.Warning(msg)
		return true, msg
	}
	//QQ头像 https://q1.qlogo.cn/g?b=qq&nk=123456789&s=100
	msg := gjson.Get(body, "message").String()
	logger.Error("QQ昵称查询接口返回", msg)
	return false, ""
}

func (d QQInfo) Desc() string {
	return "查询QQ昵称"
}

func init() {
	register("qq-info", QQInfo{})
}
