package urlscan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const metaDefenderAPI = "https://api.metadefender.com/v4/url/"

// Scan scans a given URL using the MetaDefender API and returns a string indicating whether the URL is "malicious" or "safe".
// It requires an API key and a URL to scan.
//
// Parameters:
//   - apiKey: A string containing the API key required for authentication.
//   - urlLink: A string containing the URL to be scanned.
//
// Returns:
//   - A string indicating the scan result ("malicious" or "safe").
//   - An error if any issues occur during the process, such as missing parameters, HTTP request errors, or JSON unmarshalling errors.
//
// Errors:
//   - Returns an error if the apiKey or urlLink is empty.
//   - Returns an error if there is an issue creating the HTTP request.
//   - Returns an error if there is an issue reading the response body.
//   - Returns an error if the API key is invalid (HTTP 401 Unauthorized).
//   - Returns an error if the external API returns a non-200 status code.
//   - Returns an error if there is an issue unmarshalling the JSON response.
func Scan(apiKey string, urlLink string) (string, error) {

	if apiKey == "" {
		return "", fmt.Errorf("api key is required")
	}

	if urlLink == "" {
		return "", fmt.Errorf("url is required")
	}

	encodedURL := url.QueryEscape(urlLink)

	apiUrl := metaDefenderAPI + encodedURL
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("apiKey", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("authentication failed, make sure your API Key is valid")

	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("external API error, try again later")

	}

	var responseData map[string]interface{}
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return "", err
	}

	lookupResults := responseData["lookup_results"].(map[string]interface{})
	detectedBy := lookupResults["detected_by"].(float64)

	if detectedBy != 0 {
		return "malicious", nil

	} else {
		return "safe", nil

	}

}
