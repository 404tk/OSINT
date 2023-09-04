package detectors

import (
	"fmt"
	"net/url"
	"osint/pkg/request"
	"osint/pkg/schema"
	"osint/utils/logger"

	"github.com/tidwall/gjson"
)

type ICP struct{}

func (d ICP) Run(options schema.Options) (bool, string) {
	domain, ok := options.GetMetadata("Domain")
	if !ok {
		return false, ""
	}

	query := url.Values{}
	query.Add("url", domain)
	req := &request.Req{
		Schema:   "https",
		Endpoint: "api.vvhan.com",
		Path:     "/api/icp",
		Method:   "GET",
		Header:   make(map[string]string),
		Query:    query.Encode(),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("ICP备案查询API异常", err)
		return false, ""
	}

	body := request.ReadResponseBody(resp)
	logger.Info(d.Desc(), domain)
	success := gjson.Get(body, "success").Bool()
	if success {
		info := gjson.Get(body, "info")
		msg := fmt.Sprintf(
			"主体名称：%s\n主体性质：%s\n备案号：%s\n网站名称：%s",
			info.Get("name").String(),
			info.Get("nature").String(),
			info.Get("icp").String(),
			info.Get("title").String(),
		)
		logger.Warning(msg)
		return true, msg
	}
	logger.Error("未查询到备案信息")
	return false, ""
}

func (d ICP) Desc() string {
	return "查询域名ICP备案"
}

func init() {
	register("icp", ICP{})
}
