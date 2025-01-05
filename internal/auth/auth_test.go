package auth

import (
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input, expected string
	}{
		"valid key - numbers": {"ApiKey 123456789", "123456789"},
		"valid key - chars":   {"ApiKey ThisIsAnAPIkey", "ThisIsAnAPIkey"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", strings.NewReader(""))
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Authorization", test.input)

			stringToken, err := GetAPIKey(req.Header)
			if err != nil {
				t.Fatalf("Getting API key failed: %s", err)
			}

			if !reflect.DeepEqual(stringToken, test.expected) {
				t.Fatalf("API key didn't match\nExpected: %s\nActual:   %s", test.expected, stringToken)
			}
		})

	}

}

func TestFalseAPIKey(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected error
	}{
		"Keyword trailing": {"no ApiKey", errors.New("malformed authorization header")},
		"Key missing":      {"ApiKey", errors.New("malformed authorization header")},
		"Keyword missing":  {"", errors.New("no authorization header included")},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", strings.NewReader(""))
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Authorization", test.input)

			stringToken, err := GetAPIKey(req.Header)
			if err == nil {
				t.Errorf("Getting API key should have failed. Got token: %s", stringToken)
				return
			}
			if errors.Is(err, test.expected) {
				t.Errorf("Error didn't match\nExpected: %#v\nActual:   %#v", test.expected, err)
			}
		})

	}
}
