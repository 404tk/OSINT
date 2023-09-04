package detectors

import (
	"fmt"
	"osint/pkg/request"
	"osint/pkg/schema"
	"osint/utils/logger"

	"github.com/tidwall/gjson"
)

type Mail163 struct{}

func (d Mail163) Run(options schema.Options) (bool, string) {
	username, ok := options.GetMetadata("Username")
	if !ok {
		return false, ""
	}
	// 判断用户名是否存在
	req := &request.Req{
		Schema:   "https",
		Endpoint: "regapi.mail.163.com",
		Path:     "/unireg/call.do",
		Method:   "POST",
		Header: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: fmt.Sprintf("cmd=urs.checkNameAndReco&domain=163.com&name=%s", username),
	}
	resp, err := req.Request()
	if err != nil {
		logger.Error("163邮箱查询失败", err)
		return false, ""
	}
	body := request.ReadResponseBody(resp)
	exist := gjson.Get(body, "result.exist").Int()
	if exist == 1 {
		logger.Info(d.Desc())
		msg := fmt.Sprintf("存在已注册邮箱 %s@163.com", username)
		logger.Warning(msg)
		return true, msg
	}
	logger.Error("163邮箱未找到指定用户名")
	return false, ""
}

func (d Mail163) Desc() string {
	return "163邮箱存在指定用户名"
}

func init() {
	register("mail-163", Mail163{})
}
