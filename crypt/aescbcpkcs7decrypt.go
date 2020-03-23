package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"bytes"	
)

// decryptAes256cbcpkcs7 decrypts data using AES-CBC PKCS#7 padding protocol
func decryptAes256cbcpkcs7(password, ciphtxtRaw []byte) ([]byte, error) {
	// Check ciphertext data size and blocksize ratio
	if len(ciphtxtRaw)%aes.BlockSize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	if len(ciphtxtRaw) < aes.BlockSize {
		return nil, ErrInsufficientChipherData(len(ciphtxtRaw))
	}

	// Obtain salt
	saltHeader := ciphtxtRaw[:aes.BlockSize]
	if !bytes.Equal(saltHeader[:8], openSSLSaltHeader) {
		return nil, ErrNoSaltHeader
	}

	// Obtain OpenSSL credentials
	var openSSLCredentials OpenSSLCreds
	openSSLCredentials.extract(password, saltHeader[8:])

	block, err := aes.NewCipher(openSSLCredentials[:32])
	if err != nil {
		return nil, err
	}

	// Decrypt
	cbc := cipher.NewCBCDecrypter(block, openSSLCredentials[32:])
	cbc.CryptBlocks(ciphtxtRaw[aes.BlockSize:], ciphtxtRaw[aes.BlockSize:])

	// remove PKCS#7 padding
	decrypted, err := pkcs7Unpad(ciphtxtRaw, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// pkcs7Unpad removes the padding inside the last block of data
// according to PKCS#7 padding scheme
func pkcs7Unpad(data []byte, blocksize int) ([]byte, error) {	
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if data == nil || len(data) == 0 {
		return nil, ErrInvalidPKCS7Data
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blocksize {
		return nil, ErrInvalidPKCS7Padding
	}

	if !bytes.Equal(padPatterns[padLen], data[len(data)-padLen:]) {
		return nil, ErrInvalidPKCS7Padding
	}

	return data[:len(data)-padLen], nil
}

// decryptString decrypts an encoded string that was encrypted using OpenSSL and AES-256-CBC
func decryptString(passphrase, encrypted []byte) (string, error) {
	text, err := decryptAes256cbcpkcs7(passphrase, encrypted)
	return string(text), err
}

// decryptBase64 decrypts a base64 encoded []byte that was encrypted using OpenSSL and AES-256-CBC
// currently not used
func decryptBase64(passphrase, encryptedBase64 []byte) ([]byte, error) {
	encrypted := make([]byte, base64.StdEncoding.DecodedLen(len(encryptedBase64)))
	_, err := base64.StdEncoding.Decode(encrypted, encryptedBase64)
	if err != nil {
		return nil, err
	}
	return decryptAes256cbcpkcs7(passphrase, encryptedBase64)
}

// extractOpenSSLCreds follows the OpenSSL convention for extracting the key and IV from a passphrase
// it uses the EVP_BytesToKey() method which is:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatenation,
// until there are sufficient bytes available 
// we collect 48 bytes to handle aes-256, 32 bytes for a key and 16 bytes for IV
func (c *OpenSSLCreds) extract(password, salt []byte) ([]byte, []byte) {
	m := c[:]
	buf := make([]byte, 0, 16+len(password)+len(salt))
	var prevSum [16]byte

	for i := 0; i < 3; i++ {
		n := 0
		if i > 0 {
			n = 16
		}
		buf = buf[:n+len(password)+len(salt)]
		copy(buf, prevSum[:])
		copy(buf[n:], password)
		copy(buf[n+len(password):], salt)
		prevSum = md5.Sum(buf)
		copy(m[i*16:], prevSum[:])
	}
	return c[:32], c[32:]
}