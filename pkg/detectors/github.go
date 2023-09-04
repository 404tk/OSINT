package detectors

import (
	"fmt"
	"osint/pkg/request"
	"osint/pkg/schema"
	"osint/utils"
	"osint/utils/logger"
	"strings"

	"github.com/404tk/table"
	"github.com/tidwall/gjson"
)

type Github struct{}

func (d Github) Run(options schema.Options) (bool, string) {
	username, ok := options.GetMetadata("Username")
	if !ok {
		return false, ""
	}
	// 判断用户名是否存在
	req := &request.Req{
		Schema:   "https",
		Endpoint: "api.github.com",
		Path:     fmt.Sprintf("/users/%s", username),
		Method:   "GET",
		Header: map[string]string{
			"Authorization": "Bearer " + utils.GH_Token,
			"Accept":        "application/vnd.github+json",
		},
	}
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		logger.Error("Github未找到指定用户名")
		return false, ""
	}

	logger.Info(d.Desc())
	logger.Warning("https://github.com/" + username)

	// 列举repos
	req.Path += "/repos"
	req.Query = "sort=updated&direction=asc"
	resp, err = req.Request()
	if err != nil || resp.StatusCode != 200 {
		return false, ""
	}
	body1 := request.ReadResponseBody(resp)
	repos := gjson.Parse(body1).Array()
	var results []Result
	for _, repo := range repos {
		fork := repo.Get("fork").Bool()
		if !fork {
			req.Path = fmt.Sprintf("/repos/%s/commits",
				repo.Get("full_name").String())
			req.Query = ""
			results = getCommits(req, results)
		}
	}
	if len(results) > 0 {
		msg := "查询到关联邮箱如下：\n" + table.Table(results)
		logger.Warning(msg)
		return true, "查询到关联邮箱如下：\n" + printResults(results)
	}
	logger.Error("Github未检索到邮箱信息")
	return false, ""
}

func printResults(results []Result) string {
	var msg string
	for _, r := range results {
		msg += fmt.Sprintf(
			"Username: %s,\nEMail: %s,\nSource: %s\n\n",
			r.Username, r.Email, r.Source,
		)
	}
	return msg
}

type Result struct {
	Username string
	Email    string
	Source   string
}

var emails []string

func getCommits(req *request.Req, results []Result) []Result {
	resp, err := req.Request()
	if err != nil || resp.StatusCode != 200 {
		return results
	}
	body2 := request.ReadResponseBody(resp)
	commits := gjson.Parse(body2).Array()
	for _, commit := range commits {
		name := commit.Get("commit.author.name").String()
		email := commit.Get("commit.author.email").String()
		source := commit.Get("html_url").String()
		if strings.HasSuffix(email, "users.noreply.github.com") {
			continue
		}
		if utils.IsContain(emails, email) {
			continue
		}
		emails = append(emails, email)
		results = append(results, Result{
			Username: name,
			Email:    email,
			Source:   source,
		})
	}
	return results
}

func (d Github) Desc() string {
	return "Github存在指定用户名，可查询关联邮箱"
}

func init() {
	register("github", Github{})
}
