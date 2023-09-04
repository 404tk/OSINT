package detectors

import (
	"fmt"
	"net/url"
	"osint/pkg/request"
	"osint/pkg/schema"
	"osint/utils/logger"

	"github.com/tidwall/gjson"
)

type Whois struct{}

func (d Whois) Run(options schema.Options) (bool, string) {
	domain, ok := options.GetMetadata("Domain")
	if !ok {
		return false, ""
	}

	query := url.Values{}
	query.Add("domain", domain)
	req := &request.Req{
		Schema:   "https",
		Endpoint: "whois.4.cn",
		Path:     "/api/main",
		Method:   "POST",
		Header: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: query.Encode(),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("Whois查询API异常", err)
		return false, ""
	}

	body := request.ReadResponseBody(resp)
	logger.Info(d.Desc(), domain)
	date := gjson.Get(body, "data.create_date").String()
	if date != "" {
		info := gjson.Get(body, "data")
		msg := fmt.Sprintf(
			"域名所有者：%s\n联系邮箱：%s\n注册商：%s\n注册日期：%s\n到期日期：%s",
			info.Get("owner_name").String(),
			info.Get("owner_email").String(),
			info.Get("registrars").String(),
			date,
			info.Get("expire_date").String(),
		)
		logger.Warning(msg)
		return true, msg
	}
	logger.Error("未查询到Whois信息")
	return false, ""
}

func (d Whois) Desc() string {
	return "查询域名Whois信息"
}

func init() {
	register("whois", Whois{})
}
