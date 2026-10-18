package config

import (
	"os"
	"strings"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/auth"
)

// LoadOAuth leaves unconfigured providers visible but disabled. Partial or unsafe
// configurations fail ConfigureOAuth instead of silently enabling a broken flow.
func LoadOAuth() []auth.OAuthProviderConfig {
	result := make([]auth.OAuthProviderConfig, 0, 2)
	for _, provider := range []string{"github", "google"} {
		prefix := "OAUTH_" + strings.ToUpper(provider) + "_"
		result = append(result, auth.OAuthProviderConfig{Provider: provider, ClientID: strings.TrimSpace(os.Getenv(prefix + "CLIENT_ID")), ClientSecret: os.Getenv(prefix + "CLIENT_SECRET"), RedirectURL: strings.TrimSpace(os.Getenv(prefix + "REDIRECT_URL"))})
	}
	return result
}
