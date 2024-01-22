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

type ThreatBook struct{}

func (d ThreatBook) Run(options schema.Options) (bool, string) {
	ip, ok := options.GetMetadata("IP")
	if !ok {
		return false, ""
	}

	query := url.Values{}
	query.Add("apikey", utils.TB_APIKey)
	query.Add("exclude", "asn,rdns_list,intelligences,judgments,tags_classes,samples,update_time")
	query.Add("lang", "zh")
	query.Add("resource", ip)
	req := &request.Req{
		Schema:   "https",
		Endpoint: "api.threatbook.cn",
		Path:     "/v3/ip/query",
		Method:   "GET",
		Header:   make(map[string]string),
		Query:    query.Encode(),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("微步在线API异常", err)
		return false, ""
	}

	body := request.ReadResponseBody(resp)
	if gjson.Get(body, "response_code").Int() < 0 {
		logger.Error("微步/v3/ip/query", gjson.Get(body, "verbose_msg").String())
		return false, ""
	}
	ipinfo := gjson.Get(body, "data").Get(strings.ReplaceAll(ip, ".", "\\."))
	logger.Info(d.Desc(), ip)
	msg := printBasic(ip, ipinfo)
	ports := ipinfo.Get("ports").Array()
	if len(ports) > 0 {
		msg += "\n" + printPort(ports)
	}
	return true, msg
}

func printBasic(ip string, ipinfo gjson.Result) string {
	country := ipinfo.Get("basic.location.country").String()
	province := ipinfo.Get("basic.location.province").String()
	city := ipinfo.Get("basic.location.city").String()
	provider := ipinfo.Get("basic.carrier").String()
	scene := ipinfo.Get("scene").String()
	domains := ipinfo.Get("sum_cur_domains").Int()
	//if domains > 0 {
	// ip2Domains(ip)
	//}
	var msg string
	if province != city {
		msg = fmt.Sprintf("%s-%s-%s · %s · %s，域名反查数量为%d",
			country, province, city, provider, scene, domains)
	} else {
		msg = fmt.Sprintf("%s-%s · %s · %s，域名反查数量为%d",
			country, province, provider, scene, domains)
	}
	logger.Warning(msg)
	return msg
}

/*
func ip2Domains(ip string) {
	query := url.Values{}
	query.Add("apikey", utils.TB_APIKey)
	query.Add("exclude", "asn")
	query.Add("lang", "zh")
	query.Add("resource", ip)
	req := &request.Req{
		Schema:   "https",
		Endpoint: "api.threatbook.cn",
		Path:     "/v3/ip/adv_query",
		Method:   "GET",
		Header:   make(map[string]string),
		Query:    query.Encode(),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("微步在线API异常", err)
		return
	}
	body := request.ReadResponseBody(resp)
	if gjson.Get(body, "response_code").Int() == -1 {
		logger.Error("微步/v3/ip/adv_query", gjson.Get(body, "verbose_msg").String())
		return
	}
	//fmt.Println("body:", body)
	ipinfo := gjson.Get(body, "data.cur_domains")
	//fmt.Println("info:", ipinfo)
}
*/

func printPort(ports []gjson.Result) string {
	ver := func(values ...string) []string {
		version := []string{}
		for i, value := range values {
			if value != "" {
				if i == 2 {
					value = "(" + value + ")"
				}
				version = append(version, value)
			}
		}
		return version
	}
	msg := fmt.Sprintf("%-10s\t%-10s\t%-60s\n", "PORT", "SERVICE", "VERSION")
	for _, port := range ports {
		version := ver(
			port.Get("product").String(),
			port.Get("version").String(),
			port.Get("detail").String())
		line := fmt.Sprintf("%-10d\t%-10s\t%-60s\n",
			port.Get("port").Int(),
			port.Get("module").String(),
			strings.Join(version, " "))
		msg += line
	}
	logger.Warning("开放端口如下：\n", msg)
	return msg
}

func (d ThreatBook) Desc() string {
	return "微步在线查询IP"
}

func init() {
	register("threatbook", ThreatBook{})
}
