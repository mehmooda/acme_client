package acme

import "errors"
import "fmt"
import "runtime"

type Error struct {
	Under error
	from  string
}

func (e *Error) Error() string {
	return e.Under.Error() + e.from
}

func NewError(p error) *Error {
	e := new(Error)
	e.Under = p
	pc, fn, line, _ := runtime.Caller(1)
	e.from = fmt.Sprintf("\n\t%s[%s:%d]:", runtime.FuncForPC(pc).Name(), fn, line)
	return e
}

func NewErrorString(str string) *Error {
	e := new(Error)
	e.Under = errors.New(str)
	pc, fn, line, _ := runtime.Caller(1)
	e.from = fmt.Sprintf("\n\t%s[%s:%d]: ", runtime.FuncForPC(pc).Name(), fn, line)
	return e
}
