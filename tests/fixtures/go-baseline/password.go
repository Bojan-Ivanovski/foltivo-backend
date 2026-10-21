// Independent fixed-salt test vector using the Go baseline's Argon2 library.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/argon2"
)

func main() {
	password := "correct horse battery staple"
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	key := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)
	hash := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	out, _ := json.MarshalIndent(map[string]string{"baseline": "6fc5145a7f0983dd1a3c92a44216ec9de041df55", "password": password, "hash": hash}, "", "  ")
	fmt.Println(string(out))
}
