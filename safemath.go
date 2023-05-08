package forwardproxy

import "errors"

type _SafeMath struct {
}

var ErrOverflow = errors.New("overflow")

var SafeMath = _SafeMath{}

func (s _SafeMath) Add(a, b int64) (int64, error) {
	ret := a + b
	if ret < a || ret < b {
		return a - (a + 1), ErrOverflow
	}
	return ret, nil
}

func (s _SafeMath) Sub(a, b int64) (int64, error) {
	ret := a - b
	if ret > a {
		return 0, ErrOverflow
	}
	return ret, nil
}

func (s _SafeMath) Mul(a, b int64) (int64, error) {
	ret := a * b
	if a != 0 && ret/a != b {
		return a - (a + 1), ErrOverflow
	}
	return ret, nil
}
