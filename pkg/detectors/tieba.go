package detectors

import (
	"net/url"
	"osint/pkg/request"
	"osint/pkg/structs"
	"osint/utils/logger"
)

type TieBa struct{}

func (d TieBa) Run(args structs.ScanArgs) (bool, string) {
	if len(args.CName) == 0 {
		return false, ""
	}
	query := url.Values{}
	query.Add("un", args.CName)
	// 判断用户名是否存在
	req := &request.Req{
		Schema:   "https",
		Endpoint: "tieba.baidu.com",
		Path:     "/home/main/",
		Method:   "GET",
		Header:   make(map[string]string),
		Query:    query.Encode(),
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("百度贴吧未找到指定用户名")
		return false, ""
	}
	logger.Info(d.Desc())
	logger.Warning(resp.Request.URL.String())
	return true, resp.Request.URL.String()
}

func (d TieBa) Desc() string {
	return "百度贴吧存在指定用户名"
}

func init() {
	register("tieba", TieBa{})
}
