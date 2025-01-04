package auth

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"ApiKey 123456789", "123456789"},
		{"ApiKey ThisIsAnAPIkey", "ThisIsAnAPIkey"},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", "/", strings.NewReader(""))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", test.input)

		stringToken, err := GetAPIKey(req.Header)
		if err != nil {
			t.Errorf("Getting API key failed: %s", err)
			return
		}
		if stringToken != test.expected {
			t.Errorf("API key didn't match\nExpected: %s\nActual: %s", test.expected, stringToken)
		}
	}

}

func TestFalseAPIKey(t *testing.T) {
	tests := []struct {
		input string
		fails error
	}{
		{"no ApiKey", errors.New("malformed authorization header")},
		{"ApiKey", errors.New("malformed authorization header")},
		{"", ErrNoAuthHeaderIncluded},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", "/", strings.NewReader(""))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", test.input)

		stringToken, err := GetAPIKey(req.Header)
		if err == nil {
			t.Errorf("Getting API key should have failed. Got token: %s", stringToken)
			return
		}
		if errors.Is(err, test.fails) {
			t.Errorf("Error didn't match\nExpected: %s\nActual: %s", test.fails, err)
		}
	}
}
