/**
 * OAuth2 Helper Implementation
 *
 * Provides OAuth2 authentication and connection parameter retrieval
 * for the librssconnect reference application.
 */

#include "oauth_helper.h"
#include <curl/curl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#define popen _popen
#define pclose _pclose
#else
#include <unistd.h>
#endif

namespace example
{

// Forward declaration
static size_t writeCallback(void *contents, size_t size, size_t nmemb,
                            void *userp);

/**
 * RAII wrapper for CURL handle with common configuration.
 * Automatically cleans up CURL handle and headers on destruction.
 */
class CurlRequest
{
  private:
    CURL *curl;
    struct curl_slist *headers;
    std::string *response;

  public:
    CurlRequest()
        : curl(nullptr),
          headers(nullptr),
          response(nullptr)
    {
        curl = curl_easy_init();
    }

    ~CurlRequest()
    {
        if (headers) {
            curl_slist_free_all(headers);
        }
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }

    // Disable copy
    CurlRequest(const CurlRequest &) = delete;
    CurlRequest &operator=(const CurlRequest &) = delete;

    bool isValid() const { return curl != nullptr; }

    CURL *handle() { return curl; }

    /**
     * Configure for GET request with JSON response
     */
    void setupGet(const std::string &url, std::string &responseBuffer,
                  bool insecure, const std::string &bearerToken = "")
    {
        response = &responseBuffer;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        if (insecure) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }

        headers = curl_slist_append(headers, "Accept: application/json");
        if (!bearerToken.empty()) {
            std::string authHeader = "Authorization: Bearer " + bearerToken;
            headers = curl_slist_append(headers, authHeader.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    /**
     * Configure for POST request with form data
     */
    void setupPost(const std::string &url, const std::string &postData,
                   std::string &responseBuffer, bool insecure)
    {
        response = &responseBuffer;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        if (insecure) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }

        headers = curl_slist_append(
            headers, "Content-Type: application/x-www-form-urlencoded");
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    /**
     * Configure for POST request with JSON body
     */
    void setupPostJson(const std::string &url, const std::string &jsonBody,
                       std::string &responseBuffer, bool insecure,
                       const std::string &bearerToken = "")
    {
        response = &responseBuffer;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        if (insecure) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }

        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        if (!bearerToken.empty()) {
            std::string authHeader = "Authorization: Bearer " + bearerToken;
            headers = curl_slist_append(headers, authHeader.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    /**
     * Execute the request and get HTTP status code
     */
    bool execute(long &httpCode)
    {
        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        return res == CURLE_OK;
    }
};

/**
 * Get hostId from server via /v2/hostId endpoint.
 *
 * The server returns the remote IP address as it sees the incoming connection.
 * This is critical because the server validates that the hostId in the INIT
 * message matches the actual remote address of the connection (to prevent
 * spoofing).
 *
 * When connecting through NAT/gateway, the local IP address differs from the
 * remote address seen by the server. This endpoint returns the correct value.
 *
 * @param serverUrl Server URL including protocol (e.g.,
 * "https://server.example.com")
 * @param accessToken OAuth2 access token for authentication
 * @param insecure If true, disable SSL certificate verification
 * @return Host ID (remote IP address) as seen by server, or empty string on
 * error
 */
static std::string getHostIdFromServer(const std::string &serverUrl,
                                       const std::string &accessToken,
                                       bool insecure)
{
    CurlRequest req;
    if (!req.isValid()) {
        std::cerr << "Failed to initialize CURL for hostId request"
                  << std::endl;
        return "";
    }

    // URL-encode the access token
    char *encodedToken = curl_easy_escape(req.handle(), accessToken.c_str(),
                                          accessToken.length());
    if (!encodedToken) {
        std::cerr << "Failed to URL-encode access token" << std::endl;
        return "";
    }

    std::string url = serverUrl + "/rss-servlet/api/v2/hostId?access_token=" +
                      std::string(encodedToken);
    curl_free(encodedToken);

    std::string response;
    req.setupGet(url, response, insecure);

    long httpCode = 0;
    if (!req.execute(httpCode)) {
        std::cerr << "Failed to get hostId from server: CURL error"
                  << std::endl;
        return "";
    }

    if (httpCode != 200) {
        std::cerr << "Failed to get hostId from server: HTTP " << httpCode
                  << std::endl;
        if (!response.empty()) {
            std::cerr << "Response: " << response << std::endl;
        }
        return "";
    }

    // Parse JSON response: {"hostId":"10.153.114.116"}
    size_t hostIdPos = response.find("\"hostId\"");
    if (hostIdPos == std::string::npos) {
        std::cerr << "Invalid hostId response from server" << std::endl;
        return "";
    }

    size_t valueStart = response.find("\"", hostIdPos + 9);
    if (valueStart == std::string::npos) {
        return "";
    }
    valueStart++; // Skip opening quote

    size_t valueEnd = response.find("\"", valueStart);
    if (valueEnd == std::string::npos) {
        return "";
    }

    return response.substr(valueStart, valueEnd - valueStart);
}

/**
 * Get path to ~/.pas/config.json
 * @return Full path to config file, or empty string if HOME not set
 */
static std::string getConfigPath()
{
    std::string home;
#ifdef _WIN32
    const char *userProfile = getenv("USERPROFILE");
    if (userProfile) {
        home = userProfile;
    }
#else
    const char *homeDir = getenv("HOME");
    if (homeDir) {
        home = homeDir;
    }
#endif

    if (home.empty()) {
        return "";
    }

    return home + "/.pas/config.json";
}

/**
 * Extract a JSON string value from a JSON section
 * Simple parser - does not handle escaped quotes
 * @param section JSON content to search
 * @param key JSON key to find
 * @return Value of the key, or empty string if not found
 */
static std::string extractValue(const std::string &section,
                                const std::string &key)
{
    std::string searchKey = "\"" + key + "\"";
    size_t pos = section.find(searchKey);
    if (pos == std::string::npos) {
        return "";
    }

    size_t valueStart = section.find("\"", pos + searchKey.length());
    if (valueStart == std::string::npos) {
        return "";
    }
    valueStart++;

    size_t valueEnd = section.find("\"", valueStart);
    if (valueEnd == std::string::npos) {
        return "";
    }

    return section.substr(valueStart, valueEnd - valueStart);
}

/**
 * Extract configuration section for a specific API ID from JSON
 * Finds the object associated with the given API ID key
 * @param content Full JSON config file content
 * @param apiId API ID to search for
 * @return JSON object for that API ID, or empty string if not found
 */
static std::string extractConfigSection(const std::string &content,
                                        const std::string &apiId)
{
    std::string searchKey = "\"" + apiId + "\"";
    size_t pos = content.find(searchKey);
    if (pos == std::string::npos) {
        return "";
    }

    // Find opening brace of this section
    size_t braceStart = content.find("{", pos);
    if (braceStart == std::string::npos) {
        return "";
    }

    // Find matching closing brace
    int braceCount = 1;
    size_t braceEnd = braceStart + 1;
    while (braceEnd < content.length() && braceCount > 0) {
        if (content[braceEnd] == '{')
            braceCount++;
        else if (content[braceEnd] == '}')
            braceCount--;
        braceEnd++;
    }

    if (braceCount != 0) {
        return "";
    }

    return content.substr(braceStart, braceEnd - braceStart);
}

// Load configuration for specific API ID from ~/.pas/config.json
bool loadConfig(const std::string &apiId, Config &config)
{
    std::string configPath = getConfigPath();
    if (configPath.empty()) {
        return false;
    }

    std::ifstream file(configPath);
    if (!file.is_open()) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    // Extract section for this API ID
    std::string section = extractConfigSection(content, apiId);
    if (section.empty()) {
        return false;
    }

    // Extract values from section
    config.clientId = apiId;
    config.clientSecret = extractValue(section, "client_secret");
    config.customer = extractValue(section, "customer");
    config.gatekeeper = extractValue(section, "gatekeeper");
    config.server = extractValue(section, "server");

    std::string insecureStr = extractValue(section, "insecure");
    config.insecure = (insecureStr == "true" || insecureStr == "1");

    // Set defaults
    if (config.server.empty()) {
        config.server = "https://pas.example.com";
    }

    return !config.clientSecret.empty() && !config.customer.empty() &&
           !config.gatekeeper.empty();
}

/**
 * Save updated credentials to ~/.pas/config.json
 * Updates the client_secret for the specified API ID
 */
bool saveCredentials(const std::string &apiId, const std::string &apiSecret)
{
    std::string configPath = getConfigPath();
    if (configPath.empty()) {
        std::cerr << "ERROR: Could not determine home directory\n";
        return false;
    }

    // Read existing config for this API ID
    Config config;
    if (!loadConfig(apiId, config)) {
        std::cerr << "ERROR: Could not load existing config for API ID: "
                  << apiId << "\n";
        return false;
    }

    // Update secret
    config.clientSecret = apiSecret;

    // Read entire config file
    std::ifstream inFile(configPath);
    std::string content;
    if (inFile.is_open()) {
        content = std::string((std::istreambuf_iterator<char>(inFile)),
                              std::istreambuf_iterator<char>());
        inFile.close();
    }

    // Find and replace the section for this API ID
    std::string searchKey = "\"" + apiId + "\"";
    size_t keyPos = content.find(searchKey);
    if (keyPos != std::string::npos) {
        size_t braceStart = content.find("{", keyPos);
        size_t braceEnd = braceStart + 1;
        int braceCount = 1;
        while (braceEnd < content.length() && braceCount > 0) {
            if (content[braceEnd] == '{')
                braceCount++;
            else if (content[braceEnd] == '}')
                braceCount--;
            braceEnd++;
        }

        // Build replacement section
        std::stringstream newSection;
        newSection << "{\n";
        newSection << "    \"client_secret\": \"" << config.clientSecret
                   << "\",\n";
        newSection << "    \"customer\": \"" << config.customer << "\",\n";
        newSection << "    \"gatekeeper\": \"" << config.gatekeeper << "\",\n";
        newSection << "    \"server\": \"" << config.server << "\",\n";
        newSection << "    \"insecure\": \""
                   << (config.insecure ? "true" : "false") << "\"\n";
        newSection << "  }";

        content.replace(braceStart, braceEnd - braceStart, newSection.str());
    }

    // Write updated config
    std::ofstream outFile(configPath);
    if (!outFile.is_open()) {
        std::cerr << "ERROR: Could not write to: " << configPath << "\n";
        return false;
    }

    outFile << content;
    outFile.close();

    // Set restrictive permissions (Unix only)
#ifndef _WIN32
    chmod(configPath.c_str(), 0600);
#endif

    std::cout << "Updated secret for " << apiId << " in: " << configPath
              << "\n";
    return true;
}

/**
 * Extract JSON value (string, number, or boolean)
 * Simple parser - use a real JSON library in production
 * @param json JSON content to parse
 * @param key JSON key to find
 * @return Value as string, or empty string if not found
 */
static std::string extractJsonValue(const std::string &json,
                                    const std::string &key)
{
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) {
        return "";
    }
    pos += searchKey.length();

    // Skip whitespace and colon
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == ':')) {
        pos++;
    }

    if (pos >= json.length()) {
        return "";
    }

    // Check if it's a quoted string or a number
    if (json[pos] == '"') {
        // String value
        pos++; // Skip opening quote
        size_t endPos = json.find("\"", pos);
        if (endPos == std::string::npos) {
            return "";
        }
        return json.substr(pos, endPos - pos);
    } else {
        // Numeric or boolean value - read until comma, brace, or bracket
        size_t endPos = pos;
        while (endPos < json.length() && json[endPos] != ',' &&
               json[endPos] != '}' && json[endPos] != ']' &&
               json[endPos] != '\n' && json[endPos] != '\r') {
            endPos++;
        }
        std::string value = json.substr(pos, endPos - pos);
        // Trim trailing whitespace
        while (!value.empty() &&
               (value.back() == ' ' || value.back() == '\t')) {
            value.pop_back();
        }
        return value;
    }
}

/**
 * CURL write callback - appends response data to a string
 */
static size_t writeCallback(void *contents, size_t size, size_t nmemb,
                            void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

/**
 * Authenticate with OAuth2 client credentials flow
 * Calls POST /rss-servlet/api/v2/auth/token
 */
OAuth2Result authenticateOAuth2(const std::string &serverUrl,
                                const std::string &apiId,
                                const std::string &apiSecret, bool insecure)
{
    OAuth2Result result{false, "", "", ""};

    CurlRequest req;
    if (!req.isValid()) {
        result.errorMessage = "Failed to initialize CURL";
        return result;
    }

    std::string url = serverUrl + "/rss-servlet/api/v2/auth/token";

    // URL-encode parameters (required for application/x-www-form-urlencoded)
    char *encodedApiId =
        curl_easy_escape(req.handle(), apiId.c_str(), apiId.length());
    char *encodedApiSecret =
        curl_easy_escape(req.handle(), apiSecret.c_str(), apiSecret.length());

    if (!encodedApiId || !encodedApiSecret) {
        if (encodedApiId)
            curl_free(encodedApiId);
        if (encodedApiSecret)
            curl_free(encodedApiSecret);
        result.errorMessage = "Failed to URL-encode parameters";
        return result;
    }

    // Build auth request body (no grant_type needed for PAS API)
    std::stringstream postData;
    postData << "client_id=" << encodedApiId
             << "&client_secret=" << encodedApiSecret;

    std::string postDataStr = postData.str();

    // Free encoded strings
    curl_free(encodedApiId);
    curl_free(encodedApiSecret);

    std::string response;
    req.setupPost(url, postDataStr, response, insecure);

    long httpCode = 0;
    if (!req.execute(httpCode)) {
        result.errorMessage = "CURL error during authentication";
        return result;
    }

    if (httpCode != 200) {
        result.errorMessage =
            "HTTP " + std::to_string(httpCode) + ": " + response;
        return result;
    }

    // Extract access token
    result.accessToken = extractJsonValue(response, "access_token");
    if (result.accessToken.empty()) {
        result.errorMessage =
            "Failed to extract access_token from response: " + response;
        return result;
    }

    // Extract new client secret (server rotates it after each auth)
    result.newSecret = extractJsonValue(response, "client_secret");
    if (!result.newSecret.empty()) {
        std::cerr << "\n*** IMPORTANT: Server rotated your API secret ***\n";
        std::cerr << "New secret: " << result.newSecret << "\n";
        std::cerr << "Secret will be saved to config file\n\n";
    }

    result.success = true;
    return result;
}

/**
 * Get connection parameters from PAS API.
 *
 * This function retrieves all information needed to create a launch file:
 * 1. GET /v2/site - List gatekeepers and get siteId
 * 2. POST /v2/scmkey - Get ephemeral SSH private key (valid 2 minutes)
 * 3. ssh-keyscan - Get PAS server's SSH host key
 * 4. GET /v2/hostId - Get remote IP address as seen by server
 *
 * The hostId step is critical: the server validates that the hostId in the INIT
 * message matches the remote address of the connection. When connecting through
 * NAT/gateway, the local IP differs from what the server sees.
 *
 * @param serverUrl Server URL including protocol (e.g.,
 * "https://server.example.com")
 * @param accessToken OAuth2 access token for authentication
 * @param customerName Customer name (currently unused, uses first gatekeeper)
 * @param gatekeeperName Gatekeeper name (currently unused, uses first
 * gatekeeper)
 * @param insecure If true, disable SSL certificate verification
 * @return ConnectionParams with all required information, or empty params on
 * error
 */
ConnectionParams createConnection(const std::string &serverUrl,
                                  const std::string &accessToken,
                                  const std::string &customerName,
                                  const std::string &gatekeeperName,
                                  bool insecure)
{
    // Note: customerName and gatekeeperName are not currently used
    // This simplified example uses the first gatekeeper from /v2/site
    // Production code should filter by these parameters
    (void)customerName;
    (void)gatekeeperName;

    ConnectionParams params;

    // Step 1: Get gatekeeper information from /v2/site
    std::string url = serverUrl + "/rss-servlet/api/v2/site";
    std::string response;

    {
        CurlRequest req;
        if (!req.isValid()) {
            std::cerr << "Failed to initialize CURL" << std::endl;
            return params;
        }

        req.setupGet(url, response, insecure, accessToken);

        long httpCode = 0;
        if (!req.execute(httpCode) || httpCode != 200) {
            std::cerr << "List gatekeepers failed: HTTP " << httpCode
                      << std::endl;
            if (!response.empty()) {
                std::cerr << "Response: " << response << std::endl;
            }
            return params;
        }
    }

    std::cerr << "Gatekeepers retrieved successfully!" << std::endl;
    std::cerr << "Response: " << response << std::endl;
    std::cerr << std::endl;

    // Parse gatekeeper information from response
    std::string gatekeeperId = extractJsonValue(response, "siteId");
    std::string gkGroup = extractJsonValue(response, "gkGroup");

    if (gatekeeperId.empty() || gkGroup.empty()) {
        std::cerr << "Could not find gatekeeper in response" << std::endl;
        return params;
    }

    std::cerr << "Found gatekeeper: " << gkGroup << " (ID: " << gatekeeperId
              << ")" << std::endl;
    std::cerr << std::endl;

    // Step 2: Get SSH private key from /v2/scmkey
    std::cerr << "Getting SSH private key from server..." << std::endl;

    std::string keyResponse;
    std::string keyUrl = serverUrl + "/rss-servlet/api/v2/scmkey";

    {
        CurlRequest req;
        if (!req.isValid()) {
            std::cerr << "Failed to initialize CURL for key request"
                      << std::endl;
            return params;
        }

        req.setupPostJson(keyUrl, "", keyResponse, insecure, accessToken);

        long httpCode = 0;
        if (!req.execute(httpCode) || httpCode != 200) {
            std::cerr << "Get SSH key failed: HTTP " << httpCode << std::endl;
            if (!keyResponse.empty()) {
                std::cerr << "Response: " << keyResponse << std::endl;
            }
            return params;
        }
    }

    // Extract private key from response (try both field names)
    std::string privateKey = extractJsonValue(keyResponse, "privateKey");
    if (privateKey.empty()) {
        privateKey = extractJsonValue(keyResponse, "private_key");
    }

    if (privateKey.empty()) {
        std::cerr << "Could not extract private key from response" << std::endl;
        std::cerr << "Response: " << keyResponse << std::endl;
        return params;
    }

    std::cerr << "SSH private key retrieved successfully" << std::endl;
    std::cerr << "Note: SSH key expires in 2 minutes" << std::endl;
    std::cerr << std::endl;

    // Extract server hostname from serverUrl (remove https:// for ssh-keyscan)
    std::string serverHostname = serverUrl;
    size_t protoPos = serverHostname.find("://");
    if (protoPos != std::string::npos) {
        serverHostname = serverHostname.substr(protoPos + 3);
    }

    // Step 3: Get SSH host key from the server
    // We need to connect to the SSH port and extract the host key
    std::cerr << std::endl;
    std::cerr << "Getting SSH host key from server..." << std::endl;

    std::string getHostKeyCmd =
        "ssh-keyscan -T 5 -t rsa " + serverHostname +
        " 2>/dev/null | grep -v '^#' | awk '{print $3}'";
    FILE *pipe = popen(getHostKeyCmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "Warning: Could not get SSH host key. Connection may fail "
                     "host key verification."
                  << std::endl;
        std::cerr << "Continuing without host key..." << std::endl;
    }

    std::string hostKey;
    if (pipe) {
        char buffer[4096];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            hostKey = buffer;
            // Remove trailing newline
            if (!hostKey.empty() && hostKey[hostKey.length() - 1] == '\n') {
                hostKey.erase(hostKey.length() - 1);
            }
        }
        pclose(pipe);
    }

    if (!hostKey.empty()) {
        std::cerr << "SSH host key retrieved successfully" << std::endl;
    } else {
        std::cerr << "Warning: Could not retrieve SSH host key" << std::endl;
    }

    // Get hostId from server (SDK calls /v2/hostId to get remote address as
    // seen by server) This is critical - the server validates that hostId
    // matches the remote address
    std::string hostId = getHostIdFromServer(serverUrl, accessToken, insecure);
    if (hostId.empty()) {
        std::cerr << "ERROR: Could not get hostId from server" << std::endl;
        return params;
    }
    std::cout << "Got hostId from server: " << hostId << std::endl;

    // Populate connection parameters
    params.serverHost = gkGroup;
    params.privateKey = privateKey;
    params.accessToken = accessToken;
    params.serverUrl = serverHostname;
    params.hostId = hostId;
    params.siteId = gatekeeperId;
    params.insecure = insecure;
    params.additionalParams["knownHostKey"] = hostKey;

    std::cerr << "Connection parameters ready for: " << params.serverHost
              << std::endl;
    std::cerr << "Host ID: " << params.hostId << std::endl;
    std::cerr << "Site ID: " << params.siteId << std::endl;

    return params;
}

/**
 * Generate launch file content from connection parameters.
 *
 * The launch file contains key=value pairs that configure librssconnect:
 * - serverHost: PAS server hostname (client connects here via SSH)
 * - connectKey: SSH private key (mangled/obfuscated by server)
 * - token: OAuth2 access token for API calls
 * - userId: Access token (used as userId for API-based connections)
 * - hostId: Remote IP address as seen by server (from /v2/hostId)
 * - knownHostKey: SSH host key of the PAS server (for verification)
 *
 * @param params Connection parameters from createConnection()
 * @return Launch file content in key=value format
 */
std::string generateLaunchFile(const ConnectionParams &params)
{
    std::stringstream ss;

    // PAS server hostname - client establishes SSH connection here
    ss << "serverHost=" << params.serverUrl << "\n";

    // SSH private key from /v2/scmkey (already mangled by server)
    ss << "connectKey=" << params.privateKey << "\n";

    // OAuth2 access token for API calls
    ss << "token=" << params.accessToken << "\n";

    // User ID - SDK uses the access token as userId when connecting via API
    // This ensures the SCM registers with the same user that the API token
    // authenticates as
    ss << "userId=" << params.accessToken << "\n";

    // Host ID - unique identifier for this SCM instance
    ss << "hostId=" << params.hostId << "\n";

    // SSH port (standard SSH port)
    ss << "securePort=22\n";

    // SSH host key for server verification (prevents MITM attacks)
    auto hostKeyIt = params.additionalParams.find("knownHostKey");
    if (hostKeyIt != params.additionalParams.end() &&
        !hostKeyIt->second.empty()) {
        ss << "knownHostKey=" << hostKeyIt->second << "\n";
    }

    ss << "useHttps=true\n";
    if (params.insecure) {
        ss << "scm.ignoreSSLCertificateErrors=true\n";
    }

    return ss.str();
}

/**
 * Write launch file to disk
 */
bool writeLaunchFile(const std::string &filePath, const std::string &content)
{
    std::ofstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing: " << filePath
                  << std::endl;
        return false;
    }

    file << content;
    file.close();

    if (file.fail()) {
        std::cerr << "Failed to write to file: " << filePath << std::endl;
        return false;
    }

    return true;
}

/**
 * Call v2/connection API to initiate connection to gatekeeper
 *
 * This function should be called AFTER librssconnect is running and has
 * registered with the server using the hostId. The server will find the
 * running SCM by hostId and send it the ATTACHREQUEST message.
 *
 * @param params Connection parameters (contains serverUrl, accessToken, hostId,
 * siteId)
 * @return True if connection API call succeeded
 */
bool initiateConnection(const ConnectionParams &params)
{
    CurlRequest req;
    if (!req.isValid()) {
        std::cerr << "Failed to initialize CURL for connection request"
                  << std::endl;
        return false;
    }

    // SDK uses access_token as query parameter, not Authorization header
    char *encodedToken = curl_easy_escape(
        req.handle(), params.accessToken.c_str(), params.accessToken.length());
    if (!encodedToken) {
        std::cerr << "Failed to URL-encode access token" << std::endl;
        return false;
    }
    std::string url = "https://" + params.serverUrl +
                      "/rss-servlet/api/v2/connection?access_token=" +
                      std::string(encodedToken);
    curl_free(encodedToken);

    // Build JSON body for connection request
    std::string jsonBody = "{\"siteId\":" + params.siteId + ",\"hostId\":\"" +
                           params.hostId + "\"}";

    std::string response;
    req.setupPostJson(url, jsonBody, response, params.insecure);

    long httpCode = 0;
    if (!req.execute(httpCode) || httpCode != 200) {
        std::cerr << "Connection API call failed: HTTP " << httpCode
                  << std::endl;
        if (!response.empty()) {
            std::cerr << "Response: " << response << std::endl;
        }
        return false;
    }

    std::cout << "Connection initiated successfully" << std::endl;

    return true;
}

} // namespace example
