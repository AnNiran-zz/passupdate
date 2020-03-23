# passupdate

The program decrypts archive with files, containing key, encryption data and cipher mode of operation
Uses AES-256-CBC with PKCS#7 padding algoritm and is compatible with openssl encryption and decryption: files encrypted/decrypted with openssl can be decrypted/encrypted with this code

`Mode` variable inside config files determines which encryption directory to be used

Started from main file:
Extracts file from archive is respctive archive
Decrypts them
Asks for user input for a new password set, if not provided creates a random hex

With the MD5 of the new password encrypts the decrypted data again
Creates a new archive containing the new files at the place of the previous