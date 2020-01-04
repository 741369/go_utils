package xlerror

import (
	"fmt"
	"github.com/pkg/errors"
)

type stackTracer interface {
	StackTrace() errors.StackTrace
}

type XLError struct {
	message string
}

func (e XLError) Error() string {
	return e.message
}

func (e XLError) Stack(d ...int) string {
	return GetStack(e, d...)
}

// Wrap
func Wrap(err error) error {
	return errors.WithStack(err)
}

// Wrapf
func Wrapf(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, format, args...)
}

func WithMessage(err error, message string) error {
	return errors.WithMessage(err, message)
}

func WithMessagef(err error, format string, args ...interface{}) error {
	return errors.WithMessagef(err, format, args...)
}

// New
func New(message string) error {
	return errors.WithStack(XLError{message: message})
}

// Errorf
func Errorf(format string, args ...interface{}) error {
	return errors.WithStack(XLError{message: fmt.Sprintf(format, args...)})
}

// GetStack 获取错误调用栈信息
func GetStack(err error, d ...int) string {
	e, ok := err.(stackTracer)
	if !ok {
		return ""
	}
	var depth int
	var stacktrack string
	if len(d) > 0 {
		depth = d[0] + 1
		if depth > len(e.StackTrace()) {
			depth = len(e.StackTrace())
		}
	} else {
		depth = len(e.StackTrace())
	}
	for _, f := range e.StackTrace()[1:depth] {
		stacktrack = stacktrack + fmt.Sprintf("%+s:%d\n", f, f)
	}
	return stacktrack
}
