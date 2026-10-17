package mailer

import "testing"

func TestTransportConfiguration(t *testing.T) {
	for _, tc := range []struct {
		smtp  SMTP
		local bool
		ok    bool
	}{
		{SMTP{Address: "127.0.0.1:1025", From: "noreply@localhost"}, true, true},
		{SMTP{Address: "mail.example.com:587", From: "noreply@example.com", RequireTLS: true}, false, true},
		{SMTP{Address: "mail.example.com:587", From: "noreply@example.com"}, false, false},
		{SMTP{Address: "127.0.0.1:1025", From: "noreply@localhost"}, false, false},
		{SMTP{Address: "invalid", From: "noreply@localhost"}, true, false},
		{SMTP{Address: "127.0.0.1:1025", From: "bad\r\nHeader: injected"}, true, false},
		{SMTP{Address: "127.0.0.1:1025", From: "noreply@localhost", Username: "missing-password"}, true, false},
	} {
		if err := tc.smtp.Validate(tc.local); (err == nil) != tc.ok {
			t.Fatal("transport validation failed")
		}
	}
}
