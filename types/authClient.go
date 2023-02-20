package types

type AuthorizeUser struct {
	// 授权用户的唯一标识
	OpenID string `json:"open_id"`
	// 授权用户名称
	AuthName string `json:"auth_name"`
	Name     string `json:"name,omitempty"`
	Mobile   string `json:"mobile,omitempty"`
	Email    string `json:"email,omitempty"`
}

// AuthClient Auth client interface
type AuthClient interface {
	AuthorizeURL() (string, error)
	GetAccessToken(code string) error
	RefreshToken() error
	VerifyToken() (bool, error)
	RevokeToken() error
	GetAuthorizeUser() (AuthorizeUserInter, error)
}

// AuthorizeUserInter 授权用户interface
type AuthorizeUserInter interface {
	GetUserInfo() AuthorizeUser
}

// AuthClientRespError auth client error
type AuthClientRespError interface {
	SetErrorCode(errCode int)
	SetErrorDescription(desc string)
}

type AuthClientError int

const (
	// SuccessCode success of auth
	SuccessCode AuthClientError = iota
	HttpErrorCode
	// UnmarshalErrorCode json 序列化错误
	UnmarshalErrorCode
	// UncapturedErrorCode 未捕获的错误
	UncapturedErrorCode
	// ParamsInvalidErrorCode params invalid error
	ParamsInvalidErrorCode
)
