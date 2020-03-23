package crypt

// Encrypt handle accessing of plaintext and key, returns errors if any
// from the subsequent functions and save encrypted data to file inside /encsrc/<mode>
// if calls are successful
func Encrypt() error {
	// Access plaintext data file
	plaintext, err := readEncData("plaintext")
	if err != nil {
		return err
	}

	// Access key file
	passphrase, err := readEncData("key")
	if err != nil {
		return err
	}

	// [246 164 249 159 244 198 246 248 233 193 195 136 91 35 173 31]
	// Create MD5 128-bit hash of the password word
	passphrase = md5Sum(passphrase)
	encrypted, err := encryptString(passphrase, plaintext)
	if err != nil {
		return err
	}

	// Save data to file - update content of existing "payload" file
	if err = record("payload", []byte(encrypted)); err != nil {
		return err
	}
	return nil
}
