package crypt

import (
	"io"
	"crypto/rand"
	"crypto/cipher"
	"crypto/aes"
	//"path/filepath"
	"encoding/base64"
)

// encryptAes256cbcpkcs7 encrypts plaintext data using AES-256-CBC with PKCS#7
// padding scheme
func encryptAes256cbcpkcs7(passphrase, plaintext []byte) ([]byte, error) {
	// Generate a random salt
	var salt [8]byte
	_, err := io.ReadFull(rand.Reader, salt[:])
	if err != nil {
		return nil, err
	}

	// for appending '\n'
	data := make([]byte, len(plaintext)+aes.BlockSize, len(plaintext)+aes.BlockSize+1)
	copy(data[0:], openSSLSaltHeader)
	copy(data[8:], salt[:])
	copy(data[aes.BlockSize:], plaintext)

	var creds OpenSSLCreds
	key, iv := creds.extract(passphrase, salt[:])
	
	padded, err := pkcs7Pad(data)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded[aes.BlockSize:], padded[aes.BlockSize:])

	return padded, nil
}

func pkcs7Pad(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize == 0 {
		return data, nil
	}
	padLen := 1
	for ((len(data) + padLen) % aes.BlockSize) != 0{
		padLen = padLen+1
	}
	return append(data, padPatterns[padLen]...), nil
}

// encryptString encrypts a string in a manner compatible to OpenSSL encryption
// functions using AES-256-CBC as encryption algorithm and encode to base64 format.
func encryptString(passphrase, plaintext []byte) (string, error) {
	encrypted, err := encryptAes256cbcpkcs7(passphrase, plaintext)
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}

// encryptBase64 encrypts a []byte in a manner compatible
// to OpenSSL encryption - uses AES-256-CBC encryption format
// to encode to base64
func encryptBase64(password, plaintext []byte) ([]byte, error) {
	encrypted, err := encryptAes256cbcpkcs7(password, plaintext)
	if err != nil {
		return nil, err
	}
	
	b64encrypted := make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
	base64.StdEncoding.Encode(b64encrypted, encrypted)
	return b64encrypted, nil
}