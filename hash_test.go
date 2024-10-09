package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Hash(t *testing.T) {
	hash := Hash("hello")
	verify := VerifyHash(hash, "hello")
	require.True(t, verify)

	verify2 := VerifyHash(hash, "hello2")
	require.False(t, verify2)
}

func Test_GenerateSalt(t *testing.T) {
	for i := 0; i < 10; i++ {
		salt := GenerateSalt(10)
		fmt.Println(salt)
	}
}
