package detectors

import (
	"fmt"
	"net/url"
	"osint/pkg/request"
	"osint/pkg/structs"
	"osint/utils/logger"
	"strings"

	"github.com/tidwall/gjson"
)

type CSDN struct{}

func (d CSDN) Run(args structs.ScanArgs) (bool, string) {
	if len(args.UName) == 0 {
		return false, ""
	}
	username := args.UName
	// 判断用户名是否存在
	flag, msg := queryCSDN(username)
	if !flag {
		flag, username = searchCSDN(username)
		if !flag {
			logger.Error("CSDN未找到指定用户名")
			return false, ""
		}
		flag, msg = queryCSDN(username)
		if !flag {
			logger.Error("CSDN未查到联系方式")
		}
	}
	logger.Info(d.Desc())
	if msg != "" {
		logger.Warning("https://blog.csdn.net/"+username, msg)
	} else {
		logger.Warning("https://blog.csdn.net/" + username)
	}
	return false, ""
}

func queryCSDN(user string) (bool, string) {
	req := &request.Req{
		Schema:   "https",
		Endpoint: "passport.csdn.net",
		Path:     fmt.Sprintf("/v1/service/usernames/%s", user),
		Method:   "GET",
		Header:   make(map[string]string),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		return false, ""
	}

	body := request.ReadResponseBody(resp)
	m := []string{}
	pprint := func(tag, v string) {
		if v != "" {
			m = append(m, fmt.Sprintf("%s： %s", tag, v))
		}
	}
	pprint("手机号", gjson.Get(body, "data.mobile").String())
	pprint("邮箱", gjson.Get(body, "data.email").String())
	msg := strings.Join(m, ", ")
	return true, msg
}

func searchCSDN(user string) (bool, string) {
	query := url.Values{}
	query.Add("q", user)
	query.Add("t", "userinfo")
	req := &request.Req{
		Schema:   "https",
		Endpoint: "so.csdn.net",
		Path:     "/api/v3/search",
		Method:   "GET",
		Header:   make(map[string]string),
		Query:    query.Encode(),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		return false, ""
	}
	body := request.ReadResponseBody(resp)
	res := gjson.Get(body, "result_vos").Array()
	if len(res) == 0 {
		return false, ""
	}
	for _, r := range res {
		nickname := r.Get("nickname").String()
		nickname = strings.TrimPrefix(nickname, "<em>")
		nickname = strings.TrimSuffix(nickname, "</em>")
		// 忽略大小写差异
		if strings.ToLower(nickname) == strings.ToLower(user) {
			// fmt.Println(r)
			username := r.Get("username").String()
			return true, username
		}
	}
	return false, ""
}

func (d CSDN) Desc() string {
	return "CSDN存在指定用户名"
}

func init() {
	register("csdn", CSDN{})
}
