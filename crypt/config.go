package crypt

import (
	"errors"
	"fmt"
)

// OpenSSL
type OpenSSLCreds [48]byte

// OpenSSL salt consists of "Salted__" string + 8 bytes of actual salt
var openSSLSaltHeader []byte = []byte("Salted__")

// Mode of operation
// `test` - decrypts, updates password and encrypts content in /rsc/test destination
// `standard` - decrypts, updates password and encrypts content in /rsc/standard destination
var Mode = "test"

// Errors
var ErrPathNonExistent = func (dest string) error {
	return fmt.Errorf("Destination path does not exist: %s", dest)
}

var (
	ErrInvalidBlockSize    = errors.New("Invalid blocksize")
	ErrInvalidPKCS7Data    = errors.New("Invalid PKCS7 data (empty or not padded)")
	ErrInvalidPKCS7Padding = errors.New("Invalid padding on input")

	ErrNoCiphertextData = errors.New("No encrypted data has been extracted")
	ErrNoPassphraseData = errors.New("No passphrase data has been extracted")

	ErrNoSaltHeader     = errors.New("Data does not appear to be encrypted with OpenSSL, salt header missing")
	ErrInsufficientChipherData = func(size int) error {
		return fmt.Errorf("Ciphertext data is smaller than aes block size: %i", size)
	}
)

// Filepaths
// Encrypted resources paths
var EncSrcPath      = "encsrc"
var StandardEncrRrc = "standard"
var TestEncrPath    = "test"

