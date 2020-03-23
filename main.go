package main

import (
	"fmt"
	"os"
	"crypt"
	"archive"
)

func main() {
	// Extract zipped files
	filenames, err := archive.ExtractData()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	
	// Start decryption process
	if err := crypt.Decrypt(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Update password
	if err := crypt.UpdatePassword(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Password successfully updated.")
	fmt.Println("Encrypting data with the new password ...")

	// Encrypt data with the new password
	if err := crypt.Encrypt(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	
	// Create archive with the same name containing the updated password and newly encrypted data
	if err := archive.CreateArchive(filenames); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Data is successfully encrypted with the new pasword")
}

