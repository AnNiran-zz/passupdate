package crypt

import (
	"crypto/aes"
	"bytes"
)
var padPatterns [aes.BlockSize+1][]byte

func init() {
	for i := 0; i < len(padPatterns); i++ {
		padPatterns[i] = bytes.Repeat([]byte{byte(i)}, i)
	}
}