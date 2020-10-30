package enscrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// HashPassword ...
func HashPassword(password string, v byte, prf uint, count uint) string {
	if v == 3 {
		return HashPasswordV3(password, prf, count)
	} else {
		return ""
	}
}

// VerifyPassword ..
func VerifyPassword(password string, paaswordHash string) bool {
	pwd, err := base64.StdEncoding.DecodeString(paaswordHash)
	if err != nil {
		return false
	}
	if pwd[0] == 0x01 {
		return VerifyPasswordV3(password, pwd)
	} else {
		return false
	}
}

// VerifyPasswordV3 ..
func VerifyPasswordV3(password string, pwd []byte) bool {
	prf := ReadNetworkOrder(pwd, 1)
	count := ReadNetworkOrder(pwd, 5)
	sl := ReadNetworkOrder(pwd, 9)

	salt := pwd[13:(13 + sl)]
	var subkey []byte
	if prf == 0 {
		subkey = pbkdf2.Key([]byte(password), salt, int(count), 32, sha1.New)
	} else if prf == 1 {
		subkey = pbkdf2.Key([]byte(password), salt, int(count), 32, sha256.New)
	} else {
		subkey = pbkdf2.Key([]byte(password), salt, int(count), 32, sha512.New)
	}
	if bytes.Compare(subkey, pwd[(13+sl):]) == 0 {
		return true
	} else {
		return false
	}
}

// HashPasswordV3 ..
func HashPasswordV3(password string, prf uint, count uint) string {
	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt[:])
	var subkey []byte
	if prf == 0 {
		subkey = pbkdf2.Key([]byte(password), salt, int(count), 32, sha1.New)
	} else if prf == 1 {
		subkey = pbkdf2.Key([]byte(password), salt, int(count), 32, sha256.New)
	} else {
		subkey = pbkdf2.Key([]byte(password), salt, int(count), 32, sha512.New)
	}
	fmt.Println(salt)
	result := make([]byte, 13+len(salt)+len(subkey))
	result[0] = 0x01
	WriteNetworkOrder(result, 1, prf)
	WriteNetworkOrder(result, 5, count)
	WriteNetworkOrder(result, 9, uint(len(salt)))
	copy(result[13:], salt)
	copy(result[(13+len(salt)):], subkey)
	return base64.StdEncoding.EncodeToString(result)
}

// ReadNetworkOrder ..
func ReadNetworkOrder(data []byte, offset int) uint {
	return uint(data[offset])<<24 | uint(data[offset+1])<<16 | uint(data[offset+2])<<8 | uint(data[offset+3])
}

// WriteNetworkOrder ..
func WriteNetworkOrder(data []byte, offset int, value uint) {
	data[offset] = byte(value >> 24)
	data[offset+1] = byte(value >> 16)
	data[offset+2] = byte(value >> 8)
	data[offset+3] = byte(value)
}
