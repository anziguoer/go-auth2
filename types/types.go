package types

import (
	"fmt"
)

// 默认错误
type defaultAuthClientRespError struct {
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
}

func (d *defaultAuthClientRespError) SetErrorCode(errCode int) {
	d.ErrorCode = errCode
}

func (d *defaultAuthClientRespError) SetErrorDescription(desc string) {
	d.Description = desc
}

func (d *defaultAuthClientRespError) Error() string {
	return fmt.Sprintf("error code %d, error message is %s \n", d.ErrorCode, d.Description)
}

func NewDefaultAuthClientRespError() AuthClientRespError {
	return &defaultAuthClientRespError{
		ErrorCode:   int(UncapturedErrorCode),
		Description: "Uncaptured error",
	}
}
