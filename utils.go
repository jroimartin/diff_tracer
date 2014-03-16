package main

import (
	"fmt"
)

func ParseUint64(str string) (n uint64, err error) {
	_, err = fmt.Sscan(str, &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}
