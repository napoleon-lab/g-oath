# Google OAuth Server

A Node.js Express server for handling Google OAuth authentication, specifically designed for Google Calendar API access. This server acts as an OAuth proxy, allowing clients to authenticate with Google without managing tokens directly.

## Features

- Google OAuth 2.0 flow handling
- Session-based authentication
- Rate limiting for security
- Configurable SSL/HTTP support
- Proper logging with rotation
- Input validation
- Stateless token management (clients handle their own tokens)

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

## Configuration

Create a `.env` file in the root directory with the following variables:

```env
# Required
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Optional
PORT=8321
DOMAIN=localhost
REDIRECT_PORT=8321
REDIRECT_URI=https://yourdomain.com/callback
SCOPE=https://www.googleapis.com/auth/calendar.readonly
SSL_KEY_PATH=path/to/ssl/key.pem
SSL_CERT_PATH=path/to/ssl/cert.pem
SESSION_KEY=strong_random_session_key
NODE_ENV=production
```

### Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google Calendar API
4. Create OAuth 2.0 credentials
5. Add your redirect URI: Configure via `REDIRECT_URI` environment variable, or it will be built as `http://localhost:8321/callback` using `DOMAIN` and `REDIRECT_PORT` (defaults to `http://localhost:8321/callback`)
6. Copy the Client ID and Client Secret to your `.env` file

## Usage

### Local Development
Start the server:
```bash
npm start
```

The server will automatically detect SSL certificates and use HTTPS if available, otherwise HTTP.

### Docker
Build the image:
```bash
docker build -t oauth-server .
```

Run without SSL:
```bash
docker run -p 8321:8321 --env-file .env oauth-server
```

Run with SSL (mount certificate files):
```bash
docker run -p 8321:8321 \
  --env-file .env \
  -v /path/to/ssl.key:/app/ssl.key \
  -v /path/to/ssl.crt:/app/ssl.crt \
  -e SSL_KEY_PATH=/app/ssl.key \
  -e SSL_CERT_PATH=/app/ssl.crt \
  oauth-server
```

## Endpoints

### GET /
Returns server information and available endpoints.

### GET /auth
Initiates the OAuth flow. Redirects to Google for authentication.

Query parameters:
- `state` (optional): OAuth state parameter
- `return_url` (optional): URL to return to after auth
- `redirect_uri` (optional): Client redirect URI for loopback

### GET /callback
OAuth callback endpoint. Handles the response from Google.

### GET /api/status
Returns authentication status for the current session.

Response:
```json
{
  "authenticated": true,
  "userId": "uuid",
  "email": "user@example.com"
}
```

### POST /api/refresh_with_token
Refreshes an access token using a refresh token.

Request body/query:
```json
{
  "refresh_token": "refresh_token_here"
}
```

Response:
```json
{
  "success": true,
  "access_token": "new_access_token",
  "refresh_token": "new_refresh_token",
  "expires_in": 3600,
  "expires_at": "2023-..."
}
```

### GET /logout
Clears the current session.

### GET /success
Simple success page for OAuth completion.

## Security Features

- Rate limiting (100 requests per 15 minutes, 10 auth requests per 15 minutes)
- CSRF protection via OAuth state parameter
- Input validation using Joi
- Secure session cookies (HTTPS only when SSL is enabled)
- Proper error handling without exposing sensitive information

## Logging

Logs are written to the `logs/` directory with daily rotation and a maximum retention of 7 days. In development, logs also appear in the console.

## SSL Configuration

If SSL certificate files are present at the configured paths, the server will use HTTPS. Otherwise, it falls back to HTTP (useful behind a reverse proxy with SSL termination).

## Architecture

- **Stateless**: No server-side token storage - clients manage their own tokens
- **Session-based**: Uses sessions to track authenticated users
- **Proxy**: Acts as an OAuth proxy for client applications
- **Configurable**: All settings via environment variables

## Development

For development:
```bash
NODE_ENV=development npm start
```

This enables console logging in addition to file logging.

## License

ISC