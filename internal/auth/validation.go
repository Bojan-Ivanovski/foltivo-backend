package auth

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func Email(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !utf8.ValidString(value) || len(value) > 254 || strings.ContainsAny(value, "\r\n") {
		return "", Validation("Enter a valid email address.")
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || !strings.Contains(value, ".") || strings.Contains(value, " ") {
		return "", Validation("Enter a valid email address.")
	}
	return value, nil
}

func Name(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 100 {
		return "", Validation("Name must contain between 1 and 100 characters.")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", Validation("Name cannot contain control characters.")
		}
	}
	return value, nil
}

func Password(value string) error {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 15 || utf8.RuneCountInString(value) > 128 {
		return Validation("Password must contain between 15 and 128 characters.")
	}
	return nil
}
