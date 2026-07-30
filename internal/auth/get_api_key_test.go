package auth

import (
	"errors"
	"net/http"
	"testing"
)

func headerWith(key, value string) http.Header {
	h := http.Header{}
	h.Set(key, value)
	return h
}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   error
		wantErrIs bool
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-",
		},
		{
			name:      "nil headers",
			headers:   nil,
			wantErr:   ErrNoAuthHeaderIncluded,
			wantErrIs: true,
		},
		{
			name:      "no authorization header",
			headers:   http.Header{},
			wantErr:   ErrNoAuthHeaderIncluded,
			wantErrIs: true,
		},
		{
			name:      "empty authorization header",
			headers:   http.Header{"Authorization": []string{""}},
			wantErr:   ErrNoAuthHeaderIncluded,
			wantErrIs: true,
		},
		{
			name:    "wrong scheme",
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "scheme is case sensitive",
			headers: http.Header{"Authorization": []string{"apikey my-secret-key"}},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "scheme with no key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "key with no scheme",
			headers: http.Header{"Authorization": []string{"my-secret-key"}},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "trailing space yields empty key",
			headers: http.Header{"Authorization": []string{"ApiKey "}},
			wantKey: "",
		},
		{
			name:    "extra parts are ignored",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key extra"}},
			wantKey: "my-secret-key",
		},
		{
			name:    "header name is canonicalized on set",
			headers: headerWith("authorization", "ApiKey my-secret-key"),
			wantKey: "my-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("GetAPIKey() unexpected error: %v", err)
				}
				if got != tt.wantKey {
					t.Errorf("GetAPIKey() = %q, want %q", got, tt.wantKey)
				}
				return
			}

			if err == nil {
				t.Fatalf("GetAPIKey() expected error %v, got nil", tt.wantErr)
			}
			if tt.wantErrIs {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
			} else if err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErr.Error())
			}
			if got != "" {
				t.Errorf("GetAPIKey() = %q, want empty string on error", got)
			}
		})
	}
}
