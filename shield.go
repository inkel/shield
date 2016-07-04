package shield

import (
	"crypto/sha512"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const Iterations = 5000

const MaxLength = 4096

func Check(password, encrypted []byte) bool {
	hash := encrypted[0:128]
	salt := encrypted[128:]

	return strings.Compare(digest(password, salt), string(hash)) == 0
}

func digest(password, salt []byte) string {
	dig := pbkdf2.Key(password, salt, Iterations, sha512.Size, sha512.New)

	return fmt.Sprintf("%x", dig)
}

func Encrypt(password, salt []byte) (string, error) {
	if len(password) > MaxLength {
		return "", fmt.Errorf("password is too long")
	}
	return digest(password, salt) + string(salt), nil
}
