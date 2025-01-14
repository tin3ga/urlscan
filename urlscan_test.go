package urlscan

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUrlscanAPI(t *testing.T) {
	apiKey := "" // replace with api key

	type testCase struct {
		name          string
		apiKey        string
		urlLink       string
		expected      string
		expectedError error
	}

	tests := []testCase{
		{
			name:          "Valid API Key and Safe URL",
			apiKey:        apiKey,
			urlLink:       "https://www.google.com",
			expected:      "safe",
			expectedError: nil,
		},
		{
			name:          "Valid API Key and Malicious URL",
			apiKey:        apiKey,
			urlLink:       "https://kingfamilyphotoalbum.com",
			expected:      "malicious",
			expectedError: nil,
		},
		{
			name:          "Invalid API Key",
			apiKey:        "invalid-api-key",
			urlLink:       "https://www.google.com",
			expected:      "",
			expectedError: fmt.Errorf("authentication failed, make sure your API Key is valid"),
		},
		{
			name:          "Empty URL",
			apiKey:        apiKey,
			urlLink:       "",
			expected:      "",
			expectedError: fmt.Errorf("url is required"),
		},
		{
			name:          "Empty API Key",
			apiKey:        "",
			urlLink:       "https://www.google.com",
			expected:      "",
			expectedError: fmt.Errorf("api key is required"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := Scan(test.apiKey, test.urlLink)
			assert.Equal(t, test.expected, res)

			if test.expectedError != nil {
				assert.EqualError(t, err, test.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
