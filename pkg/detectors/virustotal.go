package detectors

import (
	"fmt"
	"net/url"
	"osint/pkg/request"
	"osint/pkg/schema"
	"osint/utils"
	"osint/utils/logger"
	"strings"

	"github.com/tidwall/gjson"
)

type VirusTotal struct{}

func (d VirusTotal) Run(options schema.Options) (bool, string) {
	ip, ok := options.GetMetadata("IP")
	if !ok {
		return false, ""
	}

	query := url.Values{}
	query.Add("limit", "40")
	req := &request.Req{
		Schema:   "https",
		Endpoint: "www.virustotal.com",
		Path:     fmt.Sprintf("/api/v3/ip_addresses/%s/relationships/resolutions", ip),
		Method:   "GET",
		Header: map[string]string{
			"x-apikey": utils.VT_APIKey,
		},
		Query: query.Encode(),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("VirusTotal API异常", err)
		return false, ""
	}

	body := request.ReadResponseBody(resp)
	logger.Info(d.Desc(), ip)
	data := gjson.Get(body, "data").Array()
	if len(data) == 0 {
		logger.Error("未查询到关联域名")
		return false, ""
	}
	var domains []string
	for _, d := range data {
		domain := strings.Replace(d.Get("id").String(), ip, "", 1)
		domains = append(domains, domain)
	}
	msg := "关联域名：" + strings.Join(domains, ", ")
	logger.Warning(msg)
	return true, msg
}

func (d VirusTotal) Desc() string {
	return "VirusTotal接口IP反查域名"
}

func init() {
	register("virustotal", VirusTotal{})
}
