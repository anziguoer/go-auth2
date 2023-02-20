package idaas

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/anziguoer/go-auth2/tools"
	"github.com/anziguoer/go-auth2/types"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IDaaSConfig 竹云IDaaS 配置
type IDaaSConfig struct {
	ServerHost   string `json:"server_host"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url,omitempty"`
	state        int64  `json:"state,omitempty"`
	Scope        string `json:"scope,omitempty"`
	resp         IDaaSAuthTokenResp
}

type IDaaSRespError struct {
	// 以下两个值在错误的时候会有
	ErrorCode        int    `json:"error_code,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (IDaaSErr IDaaSRespError) Error() string {
	return fmt.Sprintf("error code %d, error message is: %s", IDaaSErr.ErrorCode, IDaaSErr.ErrorDescription)
}

// IDaaSAuthTokenResp tools 响应
type IDaaSAuthTokenResp struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	// refresh token有效期最长30天
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	State        string `json:"scope,omitempty"`
}

// VerifyTokenResp 检测token是否有效
type VerifyTokenResp struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientId  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	Exp       int    `json:"exp,omitempty"`
}

type IDssAUserInfo struct {
	Id       string `json:"id,omitempty"`
	UserName string `json:"userName,omitempty"`
	Mobile   string `json:"mobile,omitempty"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
}

// GetUserInfo get user info
func (user *IDssAUserInfo) GetUserInfo() types.AuthorizeUser {
	return types.AuthorizeUser{
		OpenID:   user.Id,
		AuthName: user.UserName,
		Name:     user.Name,
		Mobile:   user.Mobile,
		Email:    user.Email,
	}
}

// setState 设置IDaaSConfig的state
func (idsc *IDaaSConfig) setState() {
	idsc.state = time.Now().UnixMicro()
}

// getRedirectURI 回调地址
func (idsc *IDaaSConfig) getRedirectURI() string {
	if len(strings.TrimSpace(idsc.RedirectURL)) == 0 {
		return ""
	}
	return idsc.RedirectURL
}

// getAuthorization 获取header 中 Authorization参数
func (idsc *IDaaSConfig) getAuthorization() string {
	// base64(clientID:clientSecret)
	s := fmt.Sprintf("%s:%s", idsc.ClientID, idsc.ClientSecret)
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// AuthorizeURL 获取的授权地址
func (idsc *IDaaSConfig) AuthorizeURL() (string, error) {
	var uri = "/api/v1/oauth2/authorize"
	authorizeURL := fmt.Sprintf("%s%s", strings.TrimRight(idsc.ServerHost, "/"), uri)
	var urlQueryMap = make(map[string]string)
	urlQueryMap["response_type"] = "code"
	urlQueryMap["client_id"] = idsc.ClientID
	// 返回地址QueryEscape处理
	urlQueryMap["redirect_uri"] = idsc.getRedirectURI()
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", &IDaaSRespError{
			ErrorCode:        0,
			ErrorDescription: err.Error(),
		}
	}

	tools.GenerateURLQuery(u, urlQueryMap)
	return u.String(), nil
}

// GetAccessToken 获取 accessToken
func (idsc *IDaaSConfig) GetAccessToken(code string) error {
	var cusErr IDaaSRespError
	var respBody IDaaSAuthTokenResp
	if len(strings.TrimSpace(code)) == 0 {
		cusErr.ErrorCode = int(types.ParamsInvalidErrorCode)
		cusErr.ErrorDescription = "params code invalid"
		return cusErr
	}
	var uri = "/api/v1/oauth2/token"
	var requestURL = fmt.Sprintf("%s%s", strings.TrimRight(idsc.ServerHost, "/"), uri)
	var headerMap = make(map[string]string)
	headerMap["Authorization"] = "Basic " + idsc.getAuthorization() // todo
	headerMap["Content-Type"] = "application/x-www-form-urlencoded"

	var bodyMap = make(map[string]string)
	bodyMap["grant_type"] = "authorization_code"
	bodyMap["code"] = code
	bodyMap["redirect_uri"] = idsc.getRedirectURI()
	bodyStr := tools.GenerateFormBody(bodyMap)

	resp, err := tools.DoHttpRequest(http.MethodPost, requestURL, strings.NewReader(bodyStr), headerMap)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		cusErr.ErrorCode = resp.StatusCode
		if err := parseHttpResponse(resp, &cusErr); err != nil {
			cusErr.ErrorCode = resp.StatusCode
			cusErr.ErrorDescription = err.Error()
		}
		return cusErr
	}

	if err := parseHttpResponse(resp, &respBody); err != nil {
		return err
	}

	// response
	idsc.resp = respBody
	return nil
}

// RefreshToken 刷新token
func (idsc *IDaaSConfig) RefreshToken() error {
	var uri = "/api/v1/oauth2/token"
	var requestURL = fmt.Sprintf("%s%s", strings.TrimRight(idsc.ServerHost, "/"), uri)
	var headerMap = make(map[string]string)
	headerMap["Authorization"] = "Basic " + idsc.getAuthorization() // todo
	headerMap["Content-Type"] = "application/x-www-form-urlencoded"

	var bodyMap = make(map[string]string)
	bodyMap["grant_type"] = "refresh_token"
	bodyMap["refresh_token"] = idsc.resp.RefreshToken
	bodyStr := tools.GenerateFormBody(bodyMap)

	var cusErr = new(IDaaSRespError)
	resp, err := tools.DoHttpRequest(http.MethodPost, requestURL, strings.NewReader(bodyStr), headerMap)
	if err != nil {
		cusErr.ErrorCode = int(types.HttpErrorCode)
		cusErr.ErrorDescription = err.Error()
		return cusErr
	}

	if resp.StatusCode != http.StatusOK {
		cusErr.ErrorCode = resp.StatusCode
		if err := parseHttpResponse(resp, &cusErr); err != nil {
			cusErr.ErrorCode = resp.StatusCode
			cusErr.ErrorDescription = err.Error()
		}
		return cusErr
	}

	var respBody IDaaSAuthTokenResp
	if err := parseHttpResponse(resp, &respBody); err != nil {
		return err
	}
	// response
	idsc.resp = respBody
	return nil
}

// VerifyToken 校验 token 是否有效
func (idsc *IDaaSConfig) VerifyToken() (bool, error) {
	var uri = "/api/v1/oauth2/introspect"
	var requestURL = fmt.Sprintf("%s%s", strings.TrimRight(idsc.ServerHost, "/"), uri)
	var headerMap = make(map[string]string)
	headerMap["Authorization"] = "Basic " + idsc.getAuthorization() // todo
	headerMap["Content-Type"] = "application/x-www-form-urlencoded"

	var bodyMap = make(map[string]string)
	bodyMap["token"] = idsc.resp.AccessToken
	bodyMap["token_type_hint"] = "access_token"
	bodyStr := tools.GenerateFormBody(bodyMap)

	var cusErr = new(IDaaSRespError)
	resp, err := tools.DoHttpRequest(http.MethodPost, requestURL, strings.NewReader(bodyStr), headerMap)
	if err != nil {
		cusErr.ErrorCode = int(types.HttpErrorCode)
		cusErr.ErrorDescription = err.Error()
		return false, cusErr
	}

	if resp.StatusCode != http.StatusOK {
		cusErr.ErrorCode = resp.StatusCode
		if err := parseHttpResponse(resp, &cusErr); err != nil {
			cusErr.ErrorDescription = err.Error()
		}
		return false, cusErr
	}
	var respBody VerifyTokenResp
	if err := parseHttpResponse(resp, &respBody); err != nil {
		return false, cusErr
	}

	// response
	return respBody.Active, nil
}

// RevokeToken 撤销token
func (idsc *IDaaSConfig) RevokeToken() error {
	var uri = "/api/v1/oauth2/revoke"
	var requestURL = fmt.Sprintf("%s%s", strings.TrimRight(idsc.ServerHost, "/"), uri)
	var headerMap = make(map[string]string)
	headerMap["Authorization"] = "Basic " + idsc.getAuthorization() // todo
	headerMap["Content-Type"] = "application/x-www-form-urlencoded"

	var bodyMap = make(map[string]string)
	bodyMap["token"] = idsc.resp.AccessToken
	bodyMap["token_type_hint"] = "access_token"
	bodyStr := tools.GenerateFormBody(bodyMap)

	var cusErr IDaaSRespError
	resp, err := tools.DoHttpRequest(http.MethodPost, requestURL, strings.NewReader(bodyStr), headerMap)
	if err != nil {
		cusErr.ErrorCode = int(types.HttpErrorCode)
		cusErr.ErrorDescription = err.Error()
		return cusErr
	}

	// 请求失败的情况
	if resp.StatusCode != http.StatusOK {
		cusErr.ErrorCode = int(resp.StatusCode)
		if err := parseHttpResponse(resp, &cusErr); err != nil {
			cusErr.ErrorDescription = err.Error()
		}
		return cusErr
	}
	var respBody IDaaSAuthTokenResp

	// 重置token信息
	idsc.resp = respBody
	return nil
}

// GetAuthorizeUser 获取用户信息
func (idsc *IDaaSConfig) GetAuthorizeUser() (types.AuthorizeUserInter, error) {
	var uri = "/api/v1/oauth2/userinfo"
	var requestURL = fmt.Sprintf("%s%s", strings.TrimRight(idsc.ServerHost, "/"), uri)
	var headerMap = make(map[string]string)
	headerMap["Authorization"] = "Bearer " + idsc.resp.AccessToken

	var cusErr = new(IDaaSRespError)
	resp, err := tools.DoHttpRequest(http.MethodGet, requestURL, nil, headerMap)
	if err != nil {
		cusErr.ErrorCode = int(types.HttpErrorCode)
		cusErr.ErrorDescription = err.Error()
		return nil, cusErr
	}

	// 请求失败的情况
	if resp.StatusCode != http.StatusOK {
		cusErr.ErrorCode = int(types.HttpErrorCode)
		if err := parseHttpResponse(resp, &cusErr); err != nil {
			cusErr.ErrorDescription = err.Error()
		}
		return nil, cusErr
	}

	var respBody IDssAUserInfo
	if err := parseHttpResponse(resp, &respBody); err != nil {
		return nil, err
	}

	return &respBody, nil
}

// NewIDaaSAuth get the IDaaSConfig interface of types.AuthClient
func NewIDaaSAuth(serverHost, clientID, secret, redirectURL string) types.AuthClient {
	client := &IDaaSConfig{
		ServerHost:   serverHost,
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURL:  redirectURL,
		Scope:        "get_user_info",
	}
	client.setState()
	return client
}

// 只适用于竹云的解析
func parseHttpResponse(resp *http.Response, val interface{}) error {
	var cusErr IDaaSRespError
	var buf bytes.Buffer
	io.Copy(&buf, resp.Body)
	defer resp.Body.Close()
	if err := json.Unmarshal(buf.Bytes(), val); err != nil {
		cusErr.ErrorCode = int(types.UnmarshalErrorCode)
		cusErr.ErrorDescription = err.Error()
		return cusErr
	}
	return nil
}
