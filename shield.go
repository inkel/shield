package shield

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

// Iterations is the number of iterations to run PBKDF2.
const Iterations = 5000

// MaxLength indicates the maximum length that a password can have.
const MaxLength = 4096

// SaltLength is the length of the salt generated by GenerateSalt.
const SaltLength = 32

type Error string

func (e Error) Error() string { return string(e) }

const ErrPasswordTooLong = Error("password too long")

type Shield struct {
	iterations int
	maxLength  int
	saltLength int
}

func Default() Shield {
	return Shield{
		iterations: Iterations,
		maxLength:  MaxLength,
		saltLength: SaltLength}
}

// Check returns true if the supplied password matches the password+salt of encrypted.
func (s Shield) Check(password, encrypted []byte) bool {
	hash := encrypted[0:128]
	salt := encrypted[128:]

	return s.digest(password, salt) == string(hash)
}

func (s Shield) digest(password, salt []byte) string {
	dig := pbkdf2.Key(password, salt, s.iterations, sha512.Size, sha512.New)

	return hex.EncodeToString(dig)
}

// Encrypt will return a string with a salt-encrypted version of
// password. This encrypted password is self contained, in the sense
// that there's no need to store the encrypted password and salt
// separatedly, as it will have everything in the returned string.
func (s Shield) Encrypt(password, salt []byte) (string, error) {
	if len(password) > s.maxLength {
		return "", ErrPasswordTooLong
	}
	return s.digest(password, salt) + string(salt), nil
}

// GenerateSalt returns a new salt of SaltLength length filled with
// random bytes.
func (s Shield) GenerateSalt() ([]byte, error) {
	salt := make([]byte, s.saltLength)
	_, err := rand.Read(salt)
	return salt, err
}
