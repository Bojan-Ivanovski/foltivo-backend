package migrate

import "testing"

func TestUnsafeGuard(t *testing.T) {
	for _, command := range []string{"down", "reset"} {
		for _, environment := range []string{"", "production", "development", "test", "unknown"} {
			for _, allow := range []bool{true, false} {
				wantAllowed := allow && (environment == "development" || environment == "test")
				if got := CheckUnsafe(command, environment, allow) == nil; got != wantAllowed {
					t.Errorf("%s %s allow=%v: allowed=%v", command, environment, allow, got)
				}
			}
		}
	}
	if err := CheckUnsafe("up", "production", false); err != nil {
		t.Fatal(err)
	}
}
