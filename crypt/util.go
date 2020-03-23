package crypt

import (
	"io/ioutil"
	"bufio"
	"os"
	"fmt"
	"encoding/base64"
	"path/filepath"
	//"golang.org/x/crypto/pbkdf2"
)

// readRscData access file inside /rsc directory with the provided filename
// used to read data for encryption and decryption
func readEncData(filename string) ([]byte, error) {
	workPath, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	srcFile := filepath.Join(workPath, EncSrcPath, Mode, filename)
	if _, err := os.Stat(srcFile); os.IsNotExist(err) {
		return nil, ErrPathNonExistent(srcFile)
	}

	return ioutil.ReadFile(srcFile)
}

// record access a file and update its content
func record(filename string, value []byte) error {
	workPath, err := os.Getwd()
	if err != nil {
		return err
	}

	// Access file and replace content
	// we do not need to check if the file exists here because we do not depend 
	// on its content anymore
	// new file will be created if none exists
	file, err := os.OpenFile(filepath.Join(workPath, EncSrcPath, Mode, filename), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err = file.Write(value); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}

	return nil
}

// extractOpenSSLCreds follows the OpenSSL convention for extracting the key and IV from a passphrase
// it uses the EVP_BytesToKey() method which is:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatenation,
// until there are sufficient bytes available 
// we collect 48 bytes to handle aes-256, 32 bytes for a key and 16 bytes for IV
func extractOpenSSLCreds(password, salt []byte) ([]byte, []byte) {
	pass, _ := getPassword(password)
	
	crds := make([]byte, 48)
	prev := []byte{}

	for i := 0; i < 3; i++ {
		prev = md5Multiple(prev, pass, salt)
		copy(crds[i*16:], prev)
	}
	return crds[:32], crds[32:]
}

func base64File(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileSize, _ := file.Stat()
	buf := make([]byte, fileSize.Size())
	fileRead := bufio.NewReader(file)
	fileRead.Read(buf)

	return base64.StdEncoding.EncodeToString(buf), nil
}

func getPassword(password []byte) ([]byte, error) {	
	// password is text + ~
	// CameraObscrva~
	//passText := make([]byte, 14)
	//copy(passText, password[:13])
	//copy(passText[13:], password[len(password)-2:len(password)-1])
	//fmt.Println(password[len(password)-2:len(password)-1])

	//passTextMd5 := md5Sum(passText)
	//passTextMd5 = md5Sum(passTextMd5)
	
	//passTextMd5Second := md5Sum(passTextMd5)
	//fmt.Println(passTextMd5[:])
	//passTextb64 := base64.StdEncoding.EncodeToString(passText)
	//passTextMd5b64 := md5Sum([]byte(passTextb64))

	// password is text + ~\n
	// CameraObscrva + [126 10]
	//passTextnl := make([]byte, 15)
	//copy(passTextnl, password[:13])
	//copy(passTextnl[13:], password[len(password)-2:])

	//fmt.Println(passTextnl)
	//passTextnlMd5 := md5Sum(passTextnl)
	//passTextnlMd5 = md5Sum(passTextnlMd5)
	//_ = base64.StdEncoding.EncodeToString(passTextnl)
	//passTextnlMd5b64 := md5Sum([]byte(passTextnlb64))

	// passwors is all content
	//passAll := password
	//passAllb64 := base64.StdEncoding.EncodeToString(passAll)
	//passAllMd5 := md5Sum(passAll)
	//fmt.Println(string(passAllMd5[:]))
	//passAllMd5b64 := md5Sum([]byte(passAllb64))

	// password is all content - ~\n
	//passAll2 := password[:len(password)-2] --
	//passAll2Md5 := md5Sum(passAll2) --

	// password is all content - \n
	//passAll1 := password[:len(password)-1]
	// _ = base64.StdEncoding.EncodeToString(passAll1)
	//cipher, _ := readRscData("cipher")
	//sum := make([]byte, len(passAll1)+len(cipher))
	//copy(sum, passAll1)
	//copy(sum[len(password):], cipher)

	//passAll1Md5 := md5Sum(passAll1)
	//passAll1Md5 = md5Sum(passAll1Md5)
	//passAll1Md5b64 := md5Sum([]byte(passAll1b64))


	//res := base64.StdEncoding.EncodeToString(pass)
	var pass = make([]byte, 16)
	copy(pass, []byte(passwordstr))
	fmt.Println(pass)

	//pass[:128] = passTextMd5Second[:]

	// base64 encode
	//res := base64.StdEncoding.EncodeToString(pass)
	//fmt.Println(res)
	return pass, nil
}
