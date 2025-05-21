# fb-graph-enum

A command-line tool for exploring and enumerating Facebook Graph API endpoints with support for all token types. This tool automatically discovers available endpoints and fetches data. While it is possible to query the GET permissions endpoint, this endpoint is authenticated and it requires a Facebook developer account. This tool avoids it by bruteforcing the endpoints. Developed by the [Digilol](https://www.digilol.net) security team to use during penetration tests.

## Installation

```
go install github.com/digilolnet/fb-graph-enum@latest
```

## Token Types

### 1. App Access Token (Default)
Used for app-level operations and accessing public data.

```bash
./fb-graph-explorer YOUR_CLIENT_ID YOUR_CLIENT_SECRET
```

### 2. User Access Token
Used for accessing user-specific data. Requires browser authentication.

```bash
./fb-graph-explorer -token user YOUR_CLIENT_ID YOUR_CLIENT_SECRET
```

### 3. Page Access Token
Used for managing Facebook Pages. Requires a Page ID and User token with appropriate permissions.

```bash
# Authenticate user first, then get page token
./fb-graph-explorer -token page -page YOUR_PAGE_ID YOUR_CLIENT_ID YOUR_CLIENT_SECRET

# Use existing user token
./fb-graph-explorer -token page -page YOUR_PAGE_ID -user-token YOUR_USER_TOKEN YOUR_CLIENT_ID YOUR_CLIENT_SECRET
```

### 4. System User Access Token
Used for automated business operations without user interaction.

```bash
./fb-graph-explorer -token system_user -system-user YOUR_SYSTEM_USER_ID YOUR_CLIENT_ID YOUR_CLIENT_SECRET
```

## Examples

### Basic App Token Exploration
```bash
./fb-graph-explorer 1234567890 your_app_secret
```

### User Token with Custom Permissions
```bash
./fb-graph-explorer -token user -permissions "public_profile,email,user_posts,user_photos" 1234567890 your_app_secret
```

### Page Token with Verbose Output
```bash
./fb-graph-explorer -token page -page 1234567890 -verbose 1234567890 your_app_secret
```

### Save All Responses to Custom Directory
```bash
./fb-graph-explorer -save -output my_responses 1234567890 your_app_secret
```

### Long-lived User Token
```bash
./fb-graph-explorer -token user -long-lived 1234567890 your_app_secret
```

### Custom OAuth Callback Settings
```bash
./fb-graph-explorer -token user -port 9000 -callback-path /auth/callback 1234567890 your_app_secret
```

### Output

At the end of execution, you'll see a status table:

```
ENDPOINT                    STATUS      HAS DATA    STATUS CODE    ERROR
app                        ✅ SUCCESS   YES         200            
app/accounts               ❌ FAILED    NO          400            (#100) Unsupported get request
me                         ✅ SUCCESS   YES         200            
me/photos                  ⚠️ EMPTY     NO          200            
```

**Status Indicators:*
- ✅ **SUCCESS**: Request succeeded and returned data
- ⚠️ **EMPTY**: Request succeeded but returned no data
- ❌ **FAILED**: Request failed with an error

#### Saved Files

When using the `-save` flag, responses are saved as JSON files in the specified output directory:

```
fb_api_responses/
├── app.json
├── me.json
├── edge_me_photos.json
└── ...
```

## Common Issues

### Permission Errors
- Ensure your app has the required permissions
- Some endpoints require app review from Facebook
- Check that your access token has the necessary scope

### OAuth Callback Issues
- Make sure the callback URL matches your app settings
- Check that the specified port is available
- Verify firewall settings allow local server access

### Rate Limiting
- The tool includes built-in delays to respect rate limits
- If you encounter rate limiting, try running with longer delays between requests
