package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("empty auth header", func(t *testing.T) {
		_, err := GetAPIKey(http.Header{"Authorization": []string{""}})
		assertError(t, err, ErrNoAuthHeaderIncluded)
	})

	t.Run("valid auth header", func(t *testing.T) {
		apiKey, err := GetAPIKey(http.Header{"Authorization": []string{"ApiKey foobar"}})
		assertError(t, err, nil)
		assertString(t, apiKey, "foobar")
	})

	t.Run("malformed auth header", func(t *testing.T) {
		_, err := GetAPIKey(http.Header{"Authorization": []string{"Bearer foobar"}})
		assertError(t, err, errors.New("malformed authorization header"))
	})
}

func assertError(t testing.TB, got, want error) {
	t.Helper()
	if got == nil && want == nil {
		return
	}
	if got == nil || want == nil {
		t.Errorf("got %v, want %v", got, want)
		return
	}
	if !strings.Contains(got.Error(), want.Error()) {
		t.Errorf("got error %q, want error containing %q", got, want)
	}
}

func assertString(t testing.TB, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
