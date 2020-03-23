package crypt

import (
	"os"
	"io"
	"crypto/md5"
	"crypto/sha256"
)

// md5sum returns a MD5 sum of the provided resource
func md5Sum(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// md5Multiple returns a MD5 sum of provided entities 
func md5Multiple(prev, password, salt []byte) []byte {
	aqr := make([]byte, len(prev) + len(password) + len(salt))
	copy(aqr, prev)
	copy(aqr[len(prev):], password)
	copy(aqr[len(prev)+len(password):], salt)
	return md5Sum(aqr)
}

// md5HashFile returns an md5 128-bit hash of a file 
// not used currently
func md5HashFile(filename string) ([]byte, error) {
	var md5hashRes []byte

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Open a new hash interface
	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		return md5hashRes, err
	}

	md5hashRes = hash.Sum(nil)[:16]
	return md5Sum(md5hashRes), nil
}
// 
func sha256hash(rsc []byte) [32]byte {
	return sha256.Sum256(rsc)
}