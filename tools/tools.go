package tools

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GenerateFormBody
// 构造post发送的form表单数据
// name=张三&age=12&coty=北京
func GenerateFormBody(bodyMap map[string]string) string {
	var sLen = len(bodyMap)
	var formBody = make([]string, sLen)
	for k, v := range bodyMap {
		formBody[sLen-1] = fmt.Sprintf("%s=%s", k, v)
		sLen--
	}
	return strings.Join(formBody, "&")
}

// SetHttpHeader 设置http的请求头部分
func SetHttpHeader(req *http.Request, headerMap map[string]string) {
	for k, v := range headerMap {
		req.Header.Add(k, v)
	}
}

// GenerateURLQuery 构建http的query部分
// response ?name=demo&age=12
func GenerateURLQuery(url *url.URL, queryMap map[string]string) {
	query := url.Query()
	for k, v := range queryMap {
		query.Add(k, v)
	}
	url.RawQuery = query.Encode()
}

// DoHttpRequest
// 发送http request
func DoHttpRequest(method, requestURL string, body io.Reader, headerMap map[string]string) (*http.Response, error) {
	httpRequest, err := http.NewRequest(method, requestURL, body)
	if err != nil {
		return nil, err
	}

	if headerMap != nil {
		// 设置header头
		SetHttpHeader(httpRequest, headerMap)
	}

	resp, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
