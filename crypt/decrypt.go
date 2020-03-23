package crypt

// Decrypt handles data access and all corresponding errors from utility functions,
// calls decryption functionality and writes encrypted data to files if successful
func Decrypt() error {
	// Access encrypted data - payload
	ciphtxtRaw, err := readEncData("payload")
	if err != nil {
		return err
	}
	
	// Access key
	passRaw, err := readEncData("key")
	if err != nil {
		return err
	}
	
	// password is 128-bit MD5 hash of the passphrase + 16 empty bytes
	//passphrase, err := getPassword(passRaw)
	//if err != nil {
	//	return err
	//}
	passphrase := md5Sum(passRaw)
	
	// Decrypt data using the password
	decrypted, err := decryptString(passphrase[:], ciphtxtRaw)
	if err != nil {
		return err
	}

	// Save plaintext data to file
	if err = record("plaintext", []byte(decrypted[16:])); err != nil {
		return err
	}
		
	return nil
}