// Copyright 2025 İrem Kuyucu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	facebookGraphAPIBaseURL = "https://graph.facebook.com/v22.0"
	facebookOAuthURL        = "https://www.facebook.com/v22.0/dialog/oauth"
	maxDepth                = 2
	maxDataPerEndpoint      = 1000
)

var (
	verbose         bool
	outputDir       string
	saveResponses   bool
	tokenType       string
	pageId          string
	userAccessToken string
	systemUserId    string
	callbackPort    int
	callbackPath    string
	longLivedToken  bool
	permissions     string
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type APINode struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Fields   []string               `json:"fields,omitempty"`
	Edges    []string               `json:"edges,omitempty"`
}

type PaginatedResponse struct {
	Data   []interface{}          `json:"data"`
	Paging map[string]interface{} `json:"paging,omitempty"`
}

type ErrorResponse struct {
	Error struct {
		Message   string `json:"message"`
		Type      string `json:"type"`
		Code      int    `json:"code"`
		FBTraceID string `json:"fbtrace_id"`
	} `json:"error"`
}

type EndpointStatus struct {
	Path       string
	Success    bool
	StatusCode int
	ErrorMsg   string
	DataSize   int
	HasData    bool
	Data       interface{}
}

var EndpointRequiredParams = map[string]map[string]string{
	"mobile_sdk_gk": {
		"platform": "android",
	},
	"adnetworkanalytics": {
		"metrics":            "[\"FB_AD_NETWORK_BIDDING_REQUEST\",\"FB_AD_NETWORK_BIDDING_RESPONSE\",\"FB_AD_NETWORK_BIDDING_BID_RATE\",\"FB_AD_NETWORK_BIDDING_WIN_RATE\",\"FB_AD_NETWORK_REQUEST\",\"FB_AD_NETWORK_FILLED_REQUEST\",\"FB_AD_NETWORK_FILL_RATE\",\"FB_AD_NETWORK_IMP\",\"FB_AD_NETWORK_IMPRESSION_RATE\",\"FB_AD_NETWORK_CLICK\",\"FB_AD_NETWORK_CTR\",\"FB_AD_NETWORK_BIDDING_REVENUE\",\"FB_AD_NETWORK_REVENUE\",\"FB_AD_NETWORK_CPM\",\"FB_AD_NETWORK_VIDEO_GUARANTEE_REVENUE\",\"FB_AD_NETWORK_VIDEO_VIEW\",\"FB_AD_NETWORK_VIDEO_VIEW_RATE\",\"FB_AD_NETWORK_VIDEO_MRC\",\"FB_AD_NETWORK_VIDEO_MRC_RATE\",\"FB_AD_NETWORK_SHOW_RATE\"]",
		"aggregation_period": "day",
		"breakdowns":         "[\"APP\",\"PLATFORM\",\"COUNTRY\"]",
	},
	"sgw_dataset_status": {
		"dataset_id": "123456",
	},
	"sgw_install_deferral_link": {
		"dataset_id": "123456",
	},
	"adreportschedules": {
		"report_schedule_id": "12345",
	},
	"campaigns": {
		"date_preset": "last_30_days",
	},
	"adsets": {
		"date_preset": "last_30_days",
	},
	"ads": {
		"date_preset": "last_30_days",
	},
	"customaudiences": {
		"fields": "id,name,description",
	},
	"targeting_search": {
		"q":    "interests",
		"type": "adinterest",
	},
	"user_match": {
		"email": "test@example.com",
	},
	"threadedcomments": {
		"filter": "stream",
	},
	"insights": {
		"metric": "page_impressions,page_engaged_users",
		"period": "day",
	},
	"application_store_urls": {
		"platform": "facebook",
	},
	"monetized_digital_goods": {
		"platform": "ios",
	},
	"ad_studies": {
		"limit": "1000",
	},
	"leadgen_forms": {
		"page_id": "123456789",
	},
	"dynamic_posts": {
		"fields": "id,message,created_time",
	},
	"video_lists": {
		"fields": "id,title,description",
	},
	"user_photos": {
		"fields": "id,images,created_time",
	},
	"feature_upgrades": {
		"fields": "id,name,status",
	},
	"scheduled_posts": {
		"fields": "id,message,scheduled_publish_time",
	},
	"businesses": {
		"limit": "1000",
	},
	"catalog_items_batch": {
		"item_type": "product",
	},
	"assigned_partners": {
		"fields": "id,name,role",
	},
	"subscribed_domains": {
		"fields": "id,domain",
	},
}

var AdNetworkMetrics = []string{
	"FB_AD_NETWORK_BIDDING_REQUEST",
	"FB_AD_NETWORK_BIDDING_RESPONSE",
	"FB_AD_NETWORK_BIDDING_BID_RATE",
	"FB_AD_NETWORK_BIDDING_WIN_RATE",
	"FB_AD_NETWORK_REQUEST",
	"FB_AD_NETWORK_FILLED_REQUEST",
	"FB_AD_NETWORK_FILL_RATE",
	"FB_AD_NETWORK_IMP",
	"FB_AD_NETWORK_IMPRESSION_RATE",
	"FB_AD_NETWORK_CLICK",
	"FB_AD_NETWORK_CTR",
	"FB_AD_NETWORK_BIDDING_REVENUE",
	"FB_AD_NETWORK_REVENUE",
	"FB_AD_NETWORK_CPM",
	"FB_AD_NETWORK_VIDEO_GUARANTEE_REVENUE",
	"FB_AD_NETWORK_VIDEO_VIEW",
	"FB_AD_NETWORK_VIDEO_VIEW_RATE",
	"FB_AD_NETWORK_VIDEO_MRC",
	"FB_AD_NETWORK_VIDEO_MRC_RATE",
	"FB_AD_NETWORK_SHOW_RATE",
}

var endpointStatuses = make(map[string]*EndpointStatus)

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Printf(format, args...)
	}
}

// GetAppAccessToken obtains an app access token using client credentials
func GetAppAccessToken(clientID, clientSecret string) (string, error) {
	endpoint := "https://graph.facebook.com/oauth/access_token"

	values := url.Values{}
	values.Add("client_id", clientID)
	values.Add("client_secret", clientSecret)
	values.Add("grant_type", "client_credentials")

	resp, err := http.Get(endpoint + "?" + values.Encode())
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			return "", fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var tokenResponse AccessTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

// GetUserAccessToken initiates the OAuth flow to get a user access token
func GetUserAccessToken(clientID, clientSecret string) (string, error) {
	// We need to start a local HTTP server to receive the OAuth callback
	tokenChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	// Generate a random state value to prevent CSRF
	state := fmt.Sprintf("%d", time.Now().UnixNano())

	// Start a HTTP server to handle the callback
	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errorChan <- fmt.Errorf("state mismatch, possible CSRF attack")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "State mismatch, possible CSRF attack")
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			errorMsg := r.URL.Query().Get("error_description")
			if errorMsg == "" {
				errorMsg = "No code provided"
			}
			errorChan <- fmt.Errorf("authorization failed: %s", errorMsg)
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Authorization failed: %s", errorMsg)
			return
		}

		// Exchange code for access token
		accessToken, err := exchangeCodeForToken(clientID, clientSecret, code, fmt.Sprintf("http://localhost:%d%s", callbackPort, callbackPath))
		if err != nil {
			errorChan <- err
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Failed to obtain access token: %v", err)
			return
		}

		tokenChan <- accessToken
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Authentication successful! You can close this window now.")
	})

	// Start the HTTP server
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", callbackPort),
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errorChan <- fmt.Errorf("server error: %v", err)
		}
	}()
	defer server.Close()

	// Construct the OAuth URL
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&scope=%s&response_type=code",
		facebookOAuthURL,
		clientID,
		url.QueryEscape(fmt.Sprintf("http://localhost:%d%s", callbackPort, callbackPath)),
		state,
		url.QueryEscape(permissions),
	)

	fmt.Printf("Please open the following URL in your browser:\n%s\n", authURL)
	fmt.Println("Waiting for authentication...")

	// Wait for token or error
	select {
	case token := <-tokenChan:
		if longLivedToken {
			longLivedToken, err := getLongLivedUserToken(clientID, clientSecret, token)
			if err != nil {
				return "", fmt.Errorf("error exchanging for long-lived token: %v", err)
			}
			return longLivedToken, nil
		}
		return token, nil
	case err := <-errorChan:
		return "", err
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("authentication timeout")
	}
}

// exchangeCodeForToken exchanges an authorization code for an access token
func exchangeCodeForToken(clientID, clientSecret, code, redirectURI string) (string, error) {
	endpoint := "https://graph.facebook.com/v22.0/oauth/access_token"

	values := url.Values{}
	values.Add("client_id", clientID)
	values.Add("client_secret", clientSecret)
	values.Add("code", code)
	values.Add("redirect_uri", redirectURI)

	resp, err := http.Get(endpoint + "?" + values.Encode())
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			return "", fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var tokenResponse AccessTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

// getLongLivedUserToken exchanges a short-lived token for a long-lived one
func getLongLivedUserToken(clientID, clientSecret, accessToken string) (string, error) {
	endpoint := "https://graph.facebook.com/v22.0/oauth/access_token"

	values := url.Values{}
	values.Add("grant_type", "fb_exchange_token")
	values.Add("client_id", clientID)
	values.Add("client_secret", clientSecret)
	values.Add("fb_exchange_token", accessToken)

	resp, err := http.Get(endpoint + "?" + values.Encode())
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			return "", fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var tokenResponse AccessTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

// GetPageAccessToken gets a page access token using a user access token
func GetPageAccessToken(userAccessToken, pageID string) (string, error) {
	endpoint := fmt.Sprintf("%s/%s?fields=access_token&access_token=%s",
		facebookGraphAPIBaseURL, pageID, userAccessToken)

	resp, err := http.Get(endpoint)
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			return "", fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var response struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	if response.AccessToken == "" {
		return "", fmt.Errorf("no access token found for page %s", pageID)
	}

	return response.AccessToken, nil
}

// GetSystemUserAccessToken gets a system user access token
func GetSystemUserAccessToken(userAccessToken, systemUserID string) (string, error) {
	endpoint := fmt.Sprintf("%s/%s?fields=access_token&access_token=%s",
		facebookGraphAPIBaseURL, systemUserID, userAccessToken)

	resp, err := http.Get(endpoint)
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			return "", fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var response struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	if response.AccessToken == "" {
		return "", fmt.Errorf("no access token found for system user %s", systemUserID)
	}

	return response.AccessToken, nil
}

// GetAccessToken obtains the appropriate access token based on the token type
func GetAccessToken(clientID, clientSecret string) (string, error) {
	switch tokenType {
	case "app":
		fmt.Println("Getting App Access Token...")
		return GetAppAccessToken(clientID, clientSecret)
	case "user":
		if userAccessToken != "" {
			fmt.Println("Using provided User Access Token...")
			return userAccessToken, nil
		}
		fmt.Println("Getting User Access Token...")
		return GetUserAccessToken(clientID, clientSecret)
	case "page":
		if pageId == "" {
			return "", fmt.Errorf("page ID is required for page access token")
		}
		if userAccessToken != "" {
			fmt.Println("Getting Page Access Token using provided User Access Token...")
			return GetPageAccessToken(userAccessToken, pageId)
		}
		fmt.Println("Getting User Access Token first...")
		token, err := GetUserAccessToken(clientID, clientSecret)
		if err != nil {
			return "", err
		}
		fmt.Println("Getting Page Access Token...")
		return GetPageAccessToken(token, pageId)
	case "system_user":
		if systemUserId == "" {
			return "", fmt.Errorf("system user ID is required for system user access token")
		}
		if userAccessToken != "" {
			fmt.Println("Getting System User Access Token using provided User Access Token...")
			return GetSystemUserAccessToken(userAccessToken, systemUserId)
		}
		fmt.Println("Getting User Access Token first...")
		token, err := GetUserAccessToken(clientID, clientSecret)
		if err != nil {
			return "", err
		}
		fmt.Println("Getting System User Access Token...")
		return GetSystemUserAccessToken(token, systemUserId)
	default:
		return "", fmt.Errorf("unsupported token type: %s", tokenType)
	}
}

func FetchNodeMetadata(accessToken, nodeID string) (*APINode, error) {
	nodeURL := fmt.Sprintf("%s/%s?metadata=1&access_token=%s", facebookGraphAPIBaseURL, nodeID, accessToken)

	pathParts := strings.Split(nodeID, "/")
	endpointName := pathParts[len(pathParts)-1]

	if requiredParams, ok := EndpointRequiredParams[endpointName]; ok {
		for key, value := range requiredParams {
			nodeURL += fmt.Sprintf("&%s=%s", key, url.QueryEscape(value))
		}
	}

	resp, err := http.Get(nodeURL)
	if err != nil {
		trackEndpointStatus(nodeID, false, 0, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		trackEndpointStatus(nodeID, false, resp.StatusCode, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			trackEndpointStatus(nodeID, false, resp.StatusCode, errorResp.Error.Message, 0, false, nil)
			return nil, fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		trackEndpointStatus(nodeID, false, resp.StatusCode, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	node := &APINode{ID: nodeID}

	if name, ok := result["name"].(string); ok {
		node.Name = name
	}

	if metadata, ok := result["metadata"].(map[string]interface{}); ok {
		node.Metadata = metadata

		if fields, ok := metadata["fields"].([]interface{}); ok {
			for _, field := range fields {
				if fieldObj, ok := field.(map[string]interface{}); ok {
					if name, ok := fieldObj["name"].(string); ok {
						node.Fields = append(node.Fields, name)
					}
				}
			}
		}

		if connections, ok := metadata["connections"].(map[string]interface{}); ok {
			for connName := range connections {
				node.Edges = append(node.Edges, connName)
			}
		}
	}

	hasData := len(node.Fields) > 0 || len(node.Edges) > 0
	trackEndpointStatus(nodeID, true, resp.StatusCode, "", len(body), hasData, result)

	return node, nil
}

func FetchNodeData(accessToken, nodeID string, fields []string) (map[string]interface{}, error) {
	fieldsParam := ""
	if len(fields) > 0 {
		fieldsParam = "&fields=" + strings.Join(fields, ",")
	}

	nodeURL := fmt.Sprintf("%s/%s?access_token=%s%s", facebookGraphAPIBaseURL, nodeID, accessToken, fieldsParam)

	pathParts := strings.Split(nodeID, "/")
	endpointName := pathParts[len(pathParts)-1]

	if requiredParams, ok := EndpointRequiredParams[endpointName]; ok {
		for key, value := range requiredParams {
			nodeURL += fmt.Sprintf("&%s=%s", key, url.QueryEscape(value))
		}
	}

	resp, err := http.Get(nodeURL)
	if err != nil {
		trackEndpointStatus("node:"+nodeID, false, 0, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		trackEndpointStatus("node:"+nodeID, false, resp.StatusCode, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			trackEndpointStatus("node:"+nodeID, false, resp.StatusCode, errorResp.Error.Message, 0, false, nil)
			return nil, fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		trackEndpointStatus("node:"+nodeID, false, resp.StatusCode, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	hasData := len(result) > 0
	if len(result) <= 2 {
		if _, hasID := result["id"]; hasID {
			if _, hasName := result["name"]; hasName || len(result) == 1 {
				hasData = false
			}
		}
	}

	trackEndpointStatus("node:"+nodeID, true, resp.StatusCode, "", len(body), hasData, result)

	return result, nil
}

func FetchEdgeData(accessToken, edgeURL string, limit int) ([]interface{}, error) {
	edgePath := strings.SplitN(edgeURL, "?", 2)[0]
	edgePath = strings.Replace(edgePath, facebookGraphAPIBaseURL+"/", "", 1)

	fullURL := fmt.Sprintf("%s&limit=%d", edgeURL, limit)

	urlParts := strings.Split(edgeURL, "/")
	if len(urlParts) > 0 {
		endpointName := urlParts[len(urlParts)-1]
		queryParamIndex := strings.Index(endpointName, "?")
		if queryParamIndex != -1 {
			endpointName = endpointName[:queryParamIndex]
		}

		if endpointName == "adnetworkanalytics" {
			metricsParams := ""
			for i, metric := range AdNetworkMetrics {
				metricsParams += fmt.Sprintf("&metrics[%d]=%s", i, metric)
			}
			fullURL += metricsParams
			fullURL += "&aggregation_period=day"
			fullURL += "&breakdowns[0]=APP&breakdowns[1]=PLATFORM&breakdowns[2]=COUNTRY"
		} else {
			if requiredParams, ok := EndpointRequiredParams[endpointName]; ok {
				for key, value := range requiredParams {
					if endpointName == "adnetworkanalytics" && key == "metrics" {
						continue
					}
					fullURL += fmt.Sprintf("&%s=%s", key, url.QueryEscape(value))
				}
			}
		}
	}

	resp, err := http.Get(fullURL)
	if err != nil {
		trackEndpointStatus("edge:"+edgePath, false, 0, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		trackEndpointStatus("edge:"+edgePath, false, resp.StatusCode, err.Error(), 0, false, nil)
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if strings.Contains(string(body), "\"error\"") {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err == nil {
			trackEndpointStatus("edge:"+edgePath, false, resp.StatusCode, errorResp.Error.Message, 0, false, nil)
			return nil, fmt.Errorf("API error: %s", errorResp.Error.Message)
		}
	}

	var result PaginatedResponse
	if err := json.Unmarshal(body, &result); err != nil {
		var regularData map[string]interface{}
		if err := json.Unmarshal(body, &regularData); err != nil {
			trackEndpointStatus("edge:"+edgePath, false, resp.StatusCode, err.Error(), 0, false, nil)
			return nil, fmt.Errorf("error parsing response: %v", err)
		}

		hasData := len(regularData) > 0
		trackEndpointStatus("edge:"+edgePath, true, resp.StatusCode, "", len(body), hasData, regularData)
		return []interface{}{regularData}, nil
	}

	hasData := len(result.Data) > 0
	trackEndpointStatus("edge:"+edgePath, true, resp.StatusCode, "", len(body), hasData, result)

	return result.Data, nil
}

func GetAppID(accessToken string) (string, error) {
	appURL := fmt.Sprintf("%s/app?access_token=%s", facebookGraphAPIBaseURL, accessToken)

	resp, err := http.Get(appURL)
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	if id, ok := result["id"].(string); ok {
		return id, nil
	}

	return "", fmt.Errorf("app ID not found in response")
}

func GetAvailablePermissions(accessToken string) ([]string, error) {
	permissionsURL := fmt.Sprintf("%s/app/permissions?access_token=%s", facebookGraphAPIBaseURL, accessToken)

	resp, err := http.Get(permissionsURL)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	var permissions []string
	if data, ok := result["data"].([]interface{}); ok {
		for _, perm := range data {
			if permObj, ok := perm.(map[string]interface{}); ok {
				if name, ok := permObj["permission"].(string); ok {
					permissions = append(permissions, name)
				}
			}
		}
	}

	return permissions, nil
}

func PrettyPrintJSON(data interface{}) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("Error formatting JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))
}

func trackEndpointStatus(path string, success bool, statusCode int, errorMsg string, dataSize int, hasData bool, data interface{}) {
	endpointStatuses[path] = &EndpointStatus{
		Path:       path,
		Success:    success,
		StatusCode: statusCode,
		ErrorMsg:   errorMsg,
		DataSize:   dataSize,
		HasData:    hasData,
		Data:       data,
	}

	if saveResponses && data != nil {
		saveResponseToFile(path, data)
	}
}

func saveResponseToFile(path string, data interface{}) {
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		logVerbose("Error creating output directory: %v\n", err)
		return
	}

	filename := strings.ReplaceAll(path, "/", "_")
	filename = filepath.Join(outputDir, filename+".json")

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logVerbose("Error formatting JSON for file %s: %v\n", filename, err)
		return
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		logVerbose("Error writing file %s: %v\n", filename, err)
		return
	}

	logVerbose("Saved response to %s\n", filename)
}

func printEndpointStatusTable() {
	fmt.Println("\n\n======= SUMMARY =======")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.TabIndent)
	fmt.Fprintln(w, "ENDPOINT\tSTATUS\tHAS DATA\tSTATUS CODE\tERROR")

	var statuses []*EndpointStatus
	for _, status := range endpointStatuses {
		statuses = append(statuses, status)
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Path < statuses[j].Path
	})

	for _, status := range statuses {
		statusStr := "❌ FAILED"
		if status.Success {
			if status.HasData {
				statusStr = "✅ SUCCESS"
			} else {
				statusStr = "⚠️ EMPTY"
			}
		}

		hasDataStr := "NO"
		if status.HasData {
			hasDataStr = "YES"
		}

		statusCodeStr := "-"
		if status.StatusCode > 0 {
			statusCodeStr = fmt.Sprintf("%d", status.StatusCode)
		}

		errorMsg := status.ErrorMsg
		if len(errorMsg) > 50 {
			errorMsg = errorMsg[:47] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", status.Path, statusStr, hasDataStr, statusCodeStr, errorMsg)
	}

	w.Flush()

	if saveResponses {
		fmt.Printf("\nResponses saved to directory: %s\n", outputDir)
	}
}

func EnumerateAndFetchData(clientID, clientSecret string) error {
	logVerbose("Obtaining access token...\n")
	accessToken, err := GetAccessToken(clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("failed to get access token: %v", err)
	}
	logVerbose("Access token obtained successfully\n")

	// Determine starting nodes based on token type
	var nodesToExplore []string

	switch tokenType {
	case "app":
		nodesToExplore = []string{"app", "me"}
	case "user":
		nodesToExplore = []string{"me"}
	case "page":
		nodesToExplore = []string{pageId}
	case "system_user":
		nodesToExplore = []string{systemUserId}
	}

	// Add client ID if appropriate
	appID, err := GetAppID(accessToken)
	if err != nil {
		logVerbose("Warning: Failed to get app ID for deduplication: %v\n", err)
		appID = clientID
	}

	if tokenType == "app" && clientID != appID {
		nodesToExplore = append(nodesToExplore, clientID)
	}

	if verbose {
		logVerbose("\nFetching available permissions...\n")
		permissions, err := GetAvailablePermissions(accessToken)
		if err != nil {
			logVerbose("Failed to get permissions: %v\n", err)
		} else {
			logVerbose("Available permissions:\n")
			for _, perm := range permissions {
				logVerbose("  - %s\n", perm)
			}
		}
	}

	majorEndpoints := []string{
		"posts",
		"photos",
		"videos",
		"events",
		"groups",
		"pages",
		"ads",
		"insights",
		"feed",
		"comments",
		"likes",
		"albums",
		"accounts",
		"businesses",
		"adaccounts",
		"applications",
		"permissions",
		"messages",
		"conversations",
		"reactions",
		"locations",
		"custom_audiences",
		"catalog_products",
		"instagram_accounts",
		"mobile_sdk_gk",
		"adnetworkanalytics",
		"sgw_dataset_status",
		"sgw_install_deferral_link",
		"adcreatives",
		"campaigns",
		"shared_accounts",
		"user_invitations",
		"friends",
		"family",
		"subscriptions",
		"subscribers",
		"tagged",
		"stories",
		"lives",
		"domains",
		"leadgen_forms",
		"products",
		"payment_methods",
		"adimages",
		"ad_studies",
		"business_activities",
		"catalog_segments",
		"offline_events",
		"owned_domains",
		"assigned_users",
		"audiences",
		"content_delivery_report",
		"creative_folders",
		"custom_conversions",
		"feature_upgrades",
		"server_domains",
		"share_counts",
		"sponsorable_posts",
		"stats",
		"targeting_browse",
		"videos_metadata",
		"ad_placements",
		"product_catalogs",
		"signal_crawler_settings",
		"whatsapp_business_accounts",
	}

	explored := make(map[string]bool)

	appNodes := map[string]bool{
		"app":    true,
		appID:    true,
		clientID: true,
	}

	for _, nodeID := range nodesToExplore {
		if appNodes[nodeID] && explored["app"] {
			logVerbose("\nSkipping %s (already explored equivalent app node)\n", nodeID)
			continue
		}

		canonicalID := nodeID
		if appNodes[nodeID] {
			canonicalID = "app"
		}

		exploreAndFetchNode(accessToken, nodeID, explored, 0, canonicalID)
	}

	logVerbose("\nExploring major known endpoints:\n")
	for _, endpoint := range majorEndpoints {
		logVerbose("\n--- %s ---\n", endpoint)
		node, err := FetchNodeMetadata(accessToken, endpoint)
		if err != nil {
			logVerbose("Error: %v\n", err)
			continue
		}

		printNodeInfo(node, 0)

		fetchAndPrintNodeData(accessToken, endpoint, node, 0)
	}

	printEndpointStatusTable()

	return nil
}

func exploreAndFetchNode(accessToken, nodeID string, explored map[string]bool, depth int, canonicalID string) {
	if explored[canonicalID] || depth > maxDepth {
		return
	}
	explored[canonicalID] = true

	indent := strings.Repeat("  ", depth)
	logVerbose("\n%s--- Exploring node: %s ---\n", indent, nodeID)

	node, err := FetchNodeMetadata(accessToken, nodeID)
	if err != nil {
		logVerbose("%sError: %v\n", indent, err)
		return
	}

	printNodeInfo(node, depth)

	fetchAndPrintNodeData(accessToken, nodeID, node, depth)

	time.Sleep(200 * time.Millisecond)

	if depth < maxDepth-1 {
		for _, edge := range node.Edges {
			edgeNodeID := fmt.Sprintf("%s/%s", nodeID, edge)
			edgeCanonicalID := fmt.Sprintf("%s/%s", canonicalID, edge)

			exploreAndFetchNode(accessToken, edgeNodeID, explored, depth+1, edgeCanonicalID)
		}
	}
}

func fetchAndPrintNodeData(accessToken, nodeID string, node *APINode, depth int) {
	indent := strings.Repeat("  ", depth)

	logVerbose("%s📊 Fetching data for node: %s\n", indent, nodeID)
	data, err := FetchNodeData(accessToken, nodeID, node.Fields)
	if err != nil {
		logVerbose("%s  Error fetching data: %v\n", indent, err)
	} else {
		status, exists := endpointStatuses["node:"+nodeID]
		if exists && status.Success && status.HasData {
			// Always print successful responses with data, regardless of verbose mode
			fmt.Printf("\n%s📊 Node: %s\n", indent, nodeID)
			fmt.Printf("%s  Data:\n", indent)
			PrettyPrintJSON(data)
		} else if exists && status.Success && verbose {
			logVerbose("%s  Request successful, but no meaningful data returned.\n", indent)
		}
	}

	for _, edge := range node.Edges {
		edgeURL := fmt.Sprintf("%s/%s/%s?access_token=%s", facebookGraphAPIBaseURL, nodeID, edge, accessToken)
		edgePath := fmt.Sprintf("%s/%s", nodeID, edge)
		logVerbose("\n%s📊 Fetching data for edge: %s\n", indent, edgePath)

		edgeData, err := FetchEdgeData(accessToken, edgeURL, maxDataPerEndpoint)
		if err != nil {
			logVerbose("%s  Error fetching edge data: %v\n", indent, err)
			continue
		}

		status, exists := endpointStatuses["edge:"+edgePath]
		if exists && status.Success && status.HasData {
			// Always print successful responses with data, regardless of verbose mode
			fmt.Printf("\n%s📊 Edge: %s\n", indent, edgePath)
			fmt.Printf("%s  Data:\n", indent)
			PrettyPrintJSON(edgeData)
		} else if exists && status.Success && verbose {
			logVerbose("%s  Request successful, but no data returned.\n", indent)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func printNodeInfo(node *APINode, depth int) {
	if !verbose {
		return
	}

	indent := strings.Repeat("  ", depth)

	if node.Name != "" {
		logVerbose("%sName: %s\n", indent, node.Name)
	}

	if len(node.Fields) > 0 {
		logVerbose("%sFields:\n", indent)
		for _, field := range node.Fields {
			logVerbose("%s  - %s\n", indent, field)
		}
	}

	if len(node.Edges) > 0 {
		logVerbose("%sEdges/Connections:\n", indent)
		for _, edge := range node.Edges {
			logVerbose("%s  - %s\n", indent, edge)
		}
	}
}

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.StringVar(&outputDir, "output", "fb_api_responses", "Directory to save responses (if -save is enabled)")
	flag.BoolVar(&saveResponses, "save", false, "Save all responses to files")
	flag.StringVar(&tokenType, "token", "app", "Token type: app, user, page, or system_user")
	flag.StringVar(&pageId, "page", "", "Page ID for page access token")
	flag.StringVar(&userAccessToken, "user-token", "", "User access token (when using page or system_user token types)")
	flag.StringVar(&systemUserId, "system-user", "", "System user ID for system user access token")
	flag.IntVar(&callbackPort, "port", 8080, "Port for OAuth callback server")
	flag.StringVar(&callbackPath, "callback-path", "/facebook/callback", "Path for OAuth callback")
	flag.BoolVar(&longLivedToken, "long-lived", false, "Exchange for long-lived token")
	flag.StringVar(&permissions, "permissions", "public_profile,email,pages_show_list,pages_read_engagement", "Comma-separated list of permissions for user token")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		fmt.Println(`Usage: fb-graph-explorer [options] <client_id> <client_secret>

Options:
  -token string          Token type: app, user, page, or system_user (default "app")
  -page string           Page ID for page access token
  -user-token string     User access token (when using page or system_user token types)
  -system-user string    System user ID for system user access token
  -port int              Port for OAuth callback server (default 8080)
  -callback-path string  Path for OAuth callback (default "/facebook/callback")
  -long-lived            Exchange for long-lived token
  -permissions string    Comma-separated list of permissions for user token (default "public_profile,email,pages_show_list,pages_read_engagement")
  -verbose               Enable verbose output
  -save                  Save all responses to files
  -output string         Directory to save responses (default "fb_api_responses")

Examples:
  # App Access Token
  fb-graph-explorer -token app YOUR_CLIENT_ID YOUR_CLIENT_SECRET

  # User Access Token
  fb-graph-explorer -token user -permissions "public_profile,email" YOUR_CLIENT_ID YOUR_CLIENT_SECRET

  # Page Access Token
  fb-graph-explorer -token page -page PAGE_ID YOUR_CLIENT_ID YOUR_CLIENT_SECRET

  # System User Access Token
  fb-graph-explorer -token system_user -system-user SYSTEM_USER_ID YOUR_CLIENT_ID YOUR_CLIENT_SECRET

  # Using existing User Access Token for Page token
  fb-graph-explorer -token page -page PAGE_ID -user-token USER_ACCESS_TOKEN YOUR_CLIENT_ID YOUR_CLIENT_SECRET
`)
		os.Exit(1)
	}

	clientID := args[0]
	clientSecret := args[1]

	if err := EnumerateAndFetchData(clientID, clientSecret); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
