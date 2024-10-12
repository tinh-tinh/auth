package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Hash(t *testing.T) {
	hash := Hash("hello")
	verify := VerifyHash(hash, "hello")
	require.True(t, verify)

	verify2 := VerifyHash(hash, "hello2")
	require.False(t, verify2)

	hash3 := Hash("Jackie", 4)
	verify3 := VerifyHash(hash3, "Jack")
	require.False(t, verify3)
}

func Test_GenerateSalt(t *testing.T) {
	salts := []string{}
	for i := 0; i < 10; i++ {
		salt := GenerateSalt(10)
		salts = append(salts, salt)
	}

	require.Len(t, salts, 10)
	require.NotEqual(t, salts[0], salts[1])
}
