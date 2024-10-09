package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Crypto(t *testing.T) {
	crypto := NewCrypto("N1PCdw3M2B1TfJhoaY2mL736p2vCUc47")

	ciphertext1 := crypto.Encrypt("this is some sensitive information")
	require.NotEmpty(t, ciphertext1)

	plaintext1 := crypto.Decrypt(ciphertext1)
	require.Equal(t, "this is some sensitive information", plaintext1)

	ciphertext2 := crypto.Encrypt("hello")
	require.NotEqual(t, ciphertext1, ciphertext2)

	plaintext2 := crypto.Decrypt(ciphertext2)
	require.Equal(t, "hello", plaintext2)
}
