package request

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	userAgent string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
)

var Timeout = 10 * time.Second

func newClient(redirect bool) *http.Client {
	client := &http.Client{Timeout: Timeout}
	// 默认不跟随跳转
	if !redirect {
		var redirectFunc = func(_ *http.Request, _ []*http.Request) error {
			// Tell the http client to not follow redirect
			return http.ErrUseLastResponse
		}
		client.CheckRedirect = redirectFunc
	}
	return client
}

type Req struct {
	Schema      string
	Endpoint    string
	Path        string
	Method      string
	Header      map[string]string
	Query       string
	NotRedirect bool
	Body        string
}

// Request makes an HTTP request
func (r *Req) Request() (*http.Response, error) {
	u := &url.URL{
		Scheme:   r.Schema,
		Host:     r.Endpoint,
		Path:     r.Path,
		RawQuery: r.Query,
	}
	request, err := http.NewRequest(r.Method, u.String(), strings.NewReader(r.Body))
	if err != nil {
		return nil, err
	}

	request.Header.Set("User-Agent", userAgent)
	for k, v := range r.Header {
		request.Header.Set(k, v)
	}

	client := newClient(r.NotRedirect)

	return client.Do(request)
}

// ReadResponseBody reads response body and return string
func ReadResponseBody(response *http.Response) string {
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return ""
	}
	return string(bodyBytes)
}
