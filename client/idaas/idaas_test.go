package idaas

import (
	"fmt"
	"github.com/anziguoer/go-auth2/types"
	"testing"
)

var xxx = IDaaSConfig{
	ServerHost:   "",
	ClientID:     "",
	ClientSecret: "",
	RedirectURL:  "",
}

const code = ""

var client types.AuthClient

func TestNewIDaaSAuth(t *testing.T) {
	client = NewIDaaSAuth(xxx.ServerHost, xxx.ClientID, xxx.ClientSecret, xxx.RedirectURL)
	authorUrl, err := client.AuthorizeURL()
	if err != nil {
		t.Fatalf("获取鉴权地址: %s, %s \n", authorUrl, err)
	}
	t.Logf("获取鉴权地址: %s, %+v \n", authorUrl, err)
}

func TestIDaaSConfig_GetAccessToken(t *testing.T) {
	// 获取token -------
	client = NewIDaaSAuth(xxx.ServerHost, xxx.ClientID, xxx.ClientSecret, xxx.RedirectURL)
	err := client.GetAccessToken(code)
	if err != nil {
		t.Fatalf("获取token的response: %+v \n", err)
	}
	t.Logf("当前的token： %+v \n", client)
}

func TestIDaaSConfig_GetAuthorizeUser(t *testing.T) {
	client = NewIDaaSAuth(xxx.ServerHost, xxx.ClientID, xxx.ClientSecret, xxx.RedirectURL)
	fmt.Println("获取用户数据 ========= ")
	auth, err := client.GetAuthorizeUser()
	if err != nil {
		t.Fatalf("获取token的response: %+v \n", err)
	}
	if auth != nil {
		t.Logf("当前的用户数据： %+v \n", auth.GetUserInfo())
	}
}

func TestIDaaSConfig_RefreshToken(t *testing.T) {
	client = NewIDaaSAuth(xxx.ServerHost, xxx.ClientID, xxx.ClientSecret, xxx.RedirectURL)
	// 刷新token
	if err := client.RefreshToken(); err != nil {
		t.Fatalf("刷新token response: %+v \n", err)
	}
	t.Logf("当前的token： %+v \n", client)
}

func TestIDaaSConfig_VerifyToken(t *testing.T) {
	client = NewIDaaSAuth(xxx.ServerHost, xxx.ClientID, xxx.ClientSecret, xxx.RedirectURL)
	// 验证token
	fmt.Println("验证token有效性 ========= ")
	ok, err := client.VerifyToken()
	if err != nil {
		t.Fatalf("验证token response: %+v \n", err)
	}
	if ok {
		t.Logf("当前token 有效\n")
	} else {
		t.Logf("当前token 无效\n")
	}
}

func TestIDaaSConfig_RevokeToken(t *testing.T) {
	client = NewIDaaSAuth(xxx.ServerHost, xxx.ClientID, xxx.ClientSecret, xxx.RedirectURL)
	// 撤销token
	fmt.Println("撤销token ========= ")
	if err := client.RevokeToken(); err != nil {
		t.Fatalf("撤销token err: %+v \n", err)
	}
	t.Logf("撤销token success:\n")
	t.Logf("当前token： %+v \n", client)
}
