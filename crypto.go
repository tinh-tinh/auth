package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type Crypto struct {
	Secret []byte
}

func NewCrypto(secret string) *Crypto {
	return &Crypto{
		Secret: []byte(secret),
	}
}

func (cry *Crypto) Encrypt(plainText string) string {
	aes, err := aes.NewCipher(cry.Secret)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return string(cipherText)
}

func (cry *Crypto) Decrypt(cipherText string) string {
	aes, err := aes.NewCipher(cry.Secret)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := cipherText[:nonceSize], cipherText[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		panic(err)
	}
	return string(plaintext)
}
