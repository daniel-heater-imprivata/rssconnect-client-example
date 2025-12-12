# Reference Application for librssconnect

This example demonstrates the complete librssconnect API lifecycle for establishing secure connections to remote systems through the PAS (Privileged Access Service) architecture.

**Platforms:** Windows, macOS, Linux

## What This Example Demonstrates

1. **OAuth2 Authentication** - Client credentials flow with automatic secret rotation
2. **Gatekeeper Discovery** - Retrieving gatekeeper information via `/v2/site` REST API
3. **SSH Key Retrieval** - Getting ephemeral SSH keys from `/v2/scmkey` (valid for 2 minutes)
4. **SSH Host Key Retrieval** - Getting the PAS server's SSH host key for verification
5. **Launch File Generation** - Creating properly formatted connection parameters
6. **ConnectionManager Lifecycle** - Complete flow: create → configure → initialize → run → stop → destroy
7. **Graceful Shutdown** - Properly disconnecting and cleaning up resources

## Prerequisites

- CMake 3.15+
- librssconnect library
- curl library
- PAS server with API key configured

## Building

**Install librssconnect**
librssconnect is available from the PAS team as source or as a prebuilt library with header files.
The library and headers must be installed into valid header and library search paths for your system

## Usage

### Configuration File

Create `~/.pas/config.json` with your API credentials:

```json
{
  "your-api-id-here": {
    "client_secret": "your-secret-here",
    "customer": "your-customer-name",
    "gatekeeper": "your-gatekeeper-name",
    "server": "https://your-pas-server.com",
    "insecure": "true"
  }
}
```

**Note:** Set `"insecure": "false"` or omit it for production use with valid SSL certificates.

### Running the Example

```bash
# Run with API ID (reads config from ~/.pas/config.json)
./reference_app your-api-id-here
```

## How It Works

1. **Load Configuration** - Reads API credentials from `~/.pas/config.json`
2. **OAuth2 Authentication** - Calls `POST /v2/auth/token` with client credentials
   - Server may rotate the secret automatically
   - New secret is saved back to config file
3. **Get Gatekeeper Info** - Calls `GET /v2/site` to find the specified gatekeeper
4. **Get SSH Key** - Calls `POST /v2/scmkey` to get ephemeral SSH private key
   - Key is already mangled/obfuscated by the server
   - Key expires after 2 minutes
5. **Get SSH Host Key** - Uses `ssh-keyscan` to get PAS server's SSH host key
6. **Generate Launch File** - Creates key=value configuration file
7. **Create ConnectionManager** - Initializes librssconnect with launch file
8. **Configure** - Parses launch file and validates parameters
9. **Initialize** - Establishes SSH connection to PAS server
10. **Run** - Processes server messages (INIT, SETUSER, etc.)
11. **Stop** - Gracefully disconnects after 5 seconds (for demonstration)
12. **Cleanup** - Destroys ConnectionManager and frees resources

## Important Notes

**This is example code.** For production use:
- Use proper secrets management (not plain text config files)
- Add comprehensive error handling and retry logic
- Use a real JSON library (this example uses simple string parsing)
- Validate SSL certificates (`"insecure": "false"`)
- Use actual client IP address instead of 127.0.0.1
- Implement proper connection lifecycle management (not a 5-second timer)

**Expected Warnings:**
- Device certificate check may return 404 - normal for API-based connections
- Notification endpoint may return 404/401 - not required for connection establishment

## License

This example code is provided as-is for reference purposes.

