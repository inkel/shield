package shield

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	crypted := []byte("8cc55858f341586bde60d595d376fdafc4535d94a7383231f2adf323b5c508d2bdddd75b783b2c3acb196334288402406041cb1114ed13e6b96443b0aafccd5esalt")

	password := []byte("password")

	if !Check(password, crypted) {
		t.Fatal("should match")
	}
}

func TestEncrypt(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")

	expected := "8cc55858f341586bde60d595d376fdafc4535d94a7383231f2adf323b5c508d2bdddd75b783b2c3acb196334288402406041cb1114ed13e6b96443b0aafccd5esalt"

	crypted, err := Encrypt(password, salt)

	if err != nil {
		t.Error("Shouldn't have failed", err)
	}

	if strings.Compare(crypted, expected) != 0 {
		t.Error("expected", expected, "\n\tgot", crypted)
	}
}

func TestEncryptFailure(t *testing.T) {
	salt := []byte("salt")
	password := bytes.Repeat([]byte("p"), MaxLength+1)

	hex, err := Encrypt(password, salt)

	if hex != "" {
		t.Error("Shouldn't have returned a string")
	}

	if err == nil {
		t.Error("It should have failed")
	}
}

func TestSanity(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")

	encrypted, err := Encrypt(password, salt)

	if err != nil {
		t.Fatal(err)
	}

	if !Check(password, []byte(encrypted)) {
		t.Error("password should have checked against encrypted version")
	}
}

func BenchmarkCheck(b *testing.B) {
	crypted := []byte("8cc55858f341586bde60d595d376fdafc4535d94a7383231f2adf323b5c508d2bdddd75b783b2c3acb196334288402406041cb1114ed13e6b96443b0aafccd5esalt")
	password := []byte("password")

	for i := 0; i < b.N; i++ {
		Check(password, crypted)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	password := []byte("password")
	salt := []byte("salt")

	for i := 0; i < b.N; i++ {
		Encrypt(password, salt)
	}
}
