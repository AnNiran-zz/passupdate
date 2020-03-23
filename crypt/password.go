package crypt

import (
	"fmt"
	"bufio"
	"os"
	"strings"

	"gopkg.in/mgo.v2/bson"
)

// UpdatePassword updates the password inside /rsc/<mode>/key file
// for the following encrytpion
// if empty string is received from the input, sets up a random value used further
func UpdatePassword() error {
	fmt.Println("Please enter desired password:")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input. Please try again.")
		UpdatePassword()
	}

	password := strings.TrimSpace(response)
	// Check if provided input contains any data and create a random value
	if len(password) == 0 {
		fmt.Println("You have provided an empty password. Auto generating ...")
		password = bson.NewObjectId().Hex()
	}

	// Update new password inside key file
	if err = record("key", []byte(password)); err != nil {
		return err
	}

	return nil
}

