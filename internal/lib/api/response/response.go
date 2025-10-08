package response

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Response
// @Description all respones based on this and can overwrite this
type Response struct {
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	Payload any    `json:"payload,omitempty"`
}

const (
	StatusOK    = "OK"
	StatusError = "error"
)

func OK() Response {
	return Response{
		Status: StatusOK,
	}
}

func OKWithPayload(payload any) Response {
	return Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

func Error(err string) Response {
	return Response{
		Status: StatusError,
		Error:  err,
	}
}

func ValidationError(errs validator.ValidationErrors) Response {
	var errMsgs []string

	for _, err := range errs {
		switch err.ActualTag() {
		case "required":
			errMsgs = append(errMsgs, fmt.Sprintf("field %s is missed", err.Field()))
		default:
			errMsgs = append(errMsgs, fmt.Sprintf("field %s is not valid", err.Field()))

		}
	}

	return Response{
		Status: StatusError,
		Error:  strings.Join(errMsgs, ", "),
	}
}
