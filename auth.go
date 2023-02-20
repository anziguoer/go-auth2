package auth2

import (
	"github.com/anziguoer/go-auth2/client/idaas"
	"github.com/anziguoer/go-auth2/types"
)

const (
	IDaaSClientType  = "idaas"  // 竹云
	WechatClientType = "wechat" // 微信
)

type ClientConfig struct {
	ServerHost   string `json:"server_host"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url,omitempty"`
}

// GetAuthClient 如果存在多认证方式， 则根据client type 返回一个实例
func GetAuthClient(clientType string, cfgMap map[string]ClientConfig) types.AuthClient {
	if cfgMap == nil {
		return nil
	}

	if cfg, ok := cfgMap[clientType]; ok {
		switch clientType {
		case IDaaSClientType:
			return idaas.NewIDaaSAuth(cfg.ServerHost, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL)
		case WechatClientType:
			// 微信授权 todo
		}
	}

	return nil
}

// GetAuthServer 获取服务实例
func GetAuthServer() {
	//	do something
}
