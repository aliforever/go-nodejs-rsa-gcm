package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

func RSAKeysGenerateAndStorePEM() (privateKeyBytes, publicKeyBytes []byte, err error) {
	var privateKey *rsa.PrivateKey
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when generate private key: %s", err))
		return
	}
	publicKey := &privateKey.PublicKey

	privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	var privatePem *os.File
	privatePem, err = os.Create("private.pem")
	if err != nil {
		err = errors.New(fmt.Sprintf("error when create private.pem: %s", err))
		return
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encode private pem: %s", err))
		return
	}

	publicKeyBytes, err = x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encode public pem: %s", err))
		return
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	var publicPem *os.File
	publicPem, err = os.Create("public.pem")
	if err != nil {
		err = errors.New(fmt.Sprintf("error when create public.pem: %s", err))
		return
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encode public pem: %s", err))
		return
	}

	return
}

func RSADecodePrivateKeyFromPem() (*rsa.PrivateKey, error) {
	path := "private.pem"
	bs, _ := ioutil.ReadFile(path)
	block, _ := pem.Decode(bs)
	pKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pKey, nil
}

func AESGCMDecrypt(key, data, additionalData []byte) (decrypted []byte, err error) {
	// IV or Nonce is the first 12 bytes
	iv := data[0:12]
	data = data[12:]

	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when creating new cipher from key: %s", err))
		return
	}

	var aead cipher.AEAD
	aead, err = cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		err = errors.New(fmt.Sprintf("error when creating new gcm with block: %s", err))
		return
	}

	decrypted, err = aead.Open(nil, iv, data, additionalData)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when decrypting data using aead open: %s", err))
		return
	}
	return
}

func AESGCMEncrypt(key, data, additionalData []byte) (iv, encrypted, tag []byte, err error) {
	iv = make([]byte, 12)
	rand.Read(iv)

	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when creating cipher: %s", err))
		return
	}

	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCMWithNonceSize(block, len(iv))

	if err != nil {
		err = errors.New(fmt.Sprintf("error when creating gcm: %s", err))
		return
	}

	encrypted = aesgcm.Seal(iv, iv, data, additionalData)
	encrypted = encrypted[12:]                // Ignoring first 12 IV bytes, since we have the IV
	tag = encrypted[len(encrypted)-16:]       // Extracting last 16 bytes authentication tag
	encrypted = encrypted[:len(encrypted)-16] // Extracting raw Encrypted data without IV & Tag for use in NodeJS

	return
}

func RSAPublicKeyPKCS1Encrypt(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func RSAPrivateKeyPKCS1Decrypt(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}

func main() {
	/* Call this function to generate the keys or put the keys inside private.pem & public.pem files to be loaded
	RSAKeysGenerateAndStorePEM() */
	privateKey, err := RSADecodePrivateKeyFromPem()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Data to be encrypted by RSA PKCS1
	var data = make([]byte, 32)
	rand.Read(data)

	rsaEncryptedData, err := RSAPublicKeyPKCS1Encrypt(&privateKey.PublicKey, data)
	if err != nil {
		fmt.Println(err)
		return
	}

	rsaDecryptedData, err := RSAPrivateKeyPKCS1Decrypt(privateKey, rsaEncryptedData)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Raw Data:", data)
	fmt.Println("Encrypted Data:", rsaEncryptedData)
	fmt.Println("Decrypted Data:", rsaDecryptedData)

	key := data
	// Data to be encrypted using AES GCM
	data = []byte("Hello")
	iv, encrypted, tag, err := AESGCMEncrypt(key, data, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	// To pass these values to NodeJS you should use base64.StdEncoding.EncodeToString(data) for each of them
	fmt.Println("IV", iv)
	fmt.Println("Raw Encrypted", encrypted)
	fmt.Println("Authentication tag", tag)

	// To Decrypt from NodeJS IV (prepend) & Tag (append) should be added to the raw encrypted data first
	encrypted = append(iv, encrypted...)
	encrypted = append(encrypted, tag...)

	decrypted, err := AESGCMDecrypt(key, encrypted, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(decrypted))
}
