#pragma once

#include <map>
#include <string>

/**
 * OAuth2 Helper for librssconnect Reference Application
 *
 * Provides functions for:
 * - OAuth2 client credentials authentication
 * - Retrieving connection parameters from PAS REST API
 * - Generating launch files for librssconnect
 *
 * This is example code - adapt for your production requirements.
 */

namespace example
{

/**
 * Result of OAuth2 authentication
 */
struct OAuth2Result {
    bool success;             // True if authentication succeeded
    std::string accessToken;  // Bearer token for API calls
    std::string errorMessage; // Error description if success is false
    std::string newSecret;    // New secret if server rotated credentials
};

/**
 * Connection parameters retrieved from PAS API
 */
struct ConnectionParams {
    std::string serverHost;  // Gatekeeper hostname from /v2/site
    std::string privateKey;  // SSH private key from /v2/scmkey (mangled)
    std::string accessToken; // OAuth2 access token for API calls
    std::string serverUrl;   // PAS server hostname (without https://)
    std::string hostId;      // Remote IP address from /v2/hostId
    std::string siteId;      // Gatekeeper site ID from /v2/site
    bool insecure;           // True to disable SSL verification
    std::map<std::string, std::string>
        additionalParams; // Extra params (e.g., knownHostKey)
};

/**
 * Configuration loaded from ~/.pas/config.json
 */
struct Config {
    std::string clientId;     // OAuth2 client ID (API ID)
    std::string clientSecret; // OAuth2 client secret
    std::string customer;     // Customer name in PAS
    std::string gatekeeper;   // Gatekeeper name in PAS
    std::string server;       // PAS server URL (e.g., https://pas.example.com)
    bool insecure;            // True to disable SSL verification
};

/**
 * Load configuration from ~/.pas/config.json
 * @param apiId The API ID to look up in the config file
 * @param config Output parameter for the loaded configuration
 * @return True if config was loaded successfully
 */
bool loadConfig(const std::string &apiId, Config &config);

/**
 * Save rotated credentials to ~/.pas/config.json
 * @param apiId The API ID to update
 * @param newSecret The new client secret from the server
 * @return True if credentials were saved successfully
 */
bool saveCredentials(const std::string &apiId, const std::string &newSecret);

/**
 * Authenticate with OAuth2 client credentials flow
 * @param serverUrl PAS server URL (e.g., https://pas.example.com)
 * @param apiId OAuth2 client ID
 * @param apiSecret OAuth2 client secret
 * @param insecure True to disable SSL verification
 * @return OAuth2Result with access token or error
 */
OAuth2Result authenticateOAuth2(const std::string &serverUrl,
                                const std::string &apiId,
                                const std::string &apiSecret,
                                bool insecure = false);

/**
 * Get connection parameters from PAS API
 * Calls /v2/site to get gatekeeper info and /v2/scmkey to get SSH key
 * @param serverUrl PAS server URL
 * @param accessToken OAuth2 access token
 * @param customerName Customer name in PAS
 * @param gatekeeperName Gatekeeper name in PAS
 * @param insecure True to disable SSL verification
 * @return ConnectionParams with all required connection information
 */
ConnectionParams createConnection(const std::string &serverUrl,
                                  const std::string &accessToken,
                                  const std::string &customerName,
                                  const std::string &gatekeeperName,
                                  bool insecure = false);

/**
 * Generate launch file content from connection parameters
 * @param params Connection parameters from createConnection()
 * @return Launch file content in key=value format
 */
std::string generateLaunchFile(const ConnectionParams &params);

/**
 * Write launch file to disk
 * @param filePath Path where launch file should be written
 * @param content Launch file content from generateLaunchFile()
 * @return True if file was written successfully
 */
bool writeLaunchFile(const std::string &filePath, const std::string &content);

/**
 * Call v2/connection API to initiate connection to gatekeeper
 * This should be called AFTER librssconnect is running and registered with the
 * server. The server will find the running SCM by hostId and send it
 * ATTACHREQUEST message.
 * @param params Connection parameters (contains serverUrl, accessToken, hostId,
 * siteId)
 * @return True if connection API call succeeded
 */
bool initiateConnection(const ConnectionParams &params);

} // namespace example
