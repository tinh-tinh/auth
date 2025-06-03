package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

func Hash(str string, salt ...int) string {
	saltNumber := 10
	if len(salt) > 0 {
		saltNumber = salt[0]
	}
	saltString := GenerateSalt(saltNumber)

	h := hmac.New(sha256.New, []byte(saltString))
	h.Write([]byte(str))

	hashText := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("$2y$%d$%s.%v", saltNumber, saltString, hashText)
}

func VerifyHash(hashedStr string, plainStr string) bool {
	saltStr := strings.Split(hashedStr, "$")

	hashStr := strings.Split(saltStr[len(saltStr)-1], ".")
	saltString := hashStr[0]

	h := hmac.New(sha256.New, []byte(saltString))
	h.Write([]byte(plainStr))

	hashText := hex.EncodeToString(h.Sum(nil))

	return hashText == hashStr[1]
}

func GenerateSalt(salt int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, salt)
	for i := range salt {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}
