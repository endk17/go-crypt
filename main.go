package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// Generate RSA private key and public key and save them to a file
func GenerateRSAKey(bits int) {
	//The GenerateKey function uses the random data generator random to generate a pair of RSA keys with a specified number of words
	//Reader is a global, shared strong random number generator for passwords
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	//Save private key
	//Serialize the obtained RSA private key into der encoded string of ASN. 1 through x509 standard
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	//Use PEM format to encode the output of x509
	//Create a file to save the private key
	privateFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()

	//Build a PEM. Block structure object
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	//Save data to file
	pem.Encode(privateFile, &privateBlock)

	//Save public key
	//Get data of public key
	publicKey := privateKey.PublicKey
	//X509 encoding public key
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}

	//PEM format coding
	//Create a file to hold the public key
	publicFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()

	//Create a pem.block structure object
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	//Save to file
	pem.Encode(publicFile, &publicBlock)
}

// RSA encryption
func RSA_Encrypt(plainText []byte, path string) []byte {
	//Open file
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	//Read the contents of the file
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)

	//PEM decoding
	block, _ := pem.Decode(buf)

	//X509 decoding
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	//Type assertion
	publicKey := publicKeyInterface.(*rsa.PublicKey)

	//Encrypt plaintext
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

// RSA decryption
func RSA_Decrypt(cipherText []byte, path string) []byte {
	//Open file
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	//Get file content
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)

	//PEM decoding
	block, _ := pem.Decode(buf)

	//X509 decoding
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	//Decrypt the ciphertext
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	return plainText
}

func main() {
	//Generate key pair and save to file
	GenerateRSAKey(4096)

	message := []byte("helloworldpassword")

	//Encryption
	cipherText := RSA_Encrypt(message, "public.pem")
	fmt.Println("encrypted as:", string(cipherText))

	//Decryption
	plainText := RSA_Decrypt(cipherText, "private.pem")
	fmt.Println("decrypted as:", string(plainText))

	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword(plainText, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hashedPassword))
}
