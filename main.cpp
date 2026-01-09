/**
 * Reference Application for librssconnect
 *
 * Demonstrates the complete librssconnect API lifecycle:
 * 1. OAuth2 authentication with the PAS server
 * 2. Retrieving connection parameters via REST API
 * 3. Generating a launch file
 * 4. Establishing and managing a secure connection
 *
 * This is example code - adapt for your production requirements.
 */

#include "oauth_helper.h"
#include <ErrorInfo.h>
#include <RssConnectionManager.h>
#include <RssLogging.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

/**
 * Logging callback for librssconnect
 * Prints log messages to stdout with level prefix
 */
void loggingCallback(RssLogLevel level, char *message, void * /*userData*/)
{
    const char *levelStr = "UNKNOWN";
    switch (level) {
    case RSS_LOG_TRACE:
        levelStr = "TRACE";
        break;
    case RSS_LOG_DEBUG:
        levelStr = "DEBUG";
        break;
    case RSS_LOG_INFO:
        levelStr = "INFO ";
        break;
    case RSS_LOG_WARN:
        levelStr = "WARN ";
        break;
    case RSS_LOG_ERROR:
        levelStr = "ERROR";
        break;
    case RSS_LOG_FATAL:
        levelStr = "FATAL";
        break;
    case RSS_LOG_OFF:
        // Should never be called, but handle it
        levelStr = "OFF  ";
        break;
    }

    std::cout << "[" << levelStr << "] " << message << std::endl;
}

// Global synchronization for callbacks
namespace
{
std::mutex loggedInMutex;
std::condition_variable loggedInCondition;

std::atomic<bool> receivedLoggedIn{false};
} // namespace

/**
 * Callback for RSS message receive events
 * Detects RSSCMD_SETUSER to signal CM registration
 */
void onMessageReceived(RssMessage msg, void * /*userData*/)
{
    RssCommand cmdType = rssMessageGetCommandType(msg);

    if (cmdType == RSSCMD_SETUSER) {
        std::cout
            << "[Callback] Received SETUSER response - CM is registered\n";
        {
            std::lock_guard<std::mutex> lock(loggedInMutex);
            receivedLoggedIn = true;
        }
        loggedInCondition.notify_one();
    }
}

int main(int argc, char *argv[])
{
    // Parse command line arguments
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <api-id>\n\n";
        std::cerr << "Example:\n";
        std::cerr << "  " << argv[0]
                  << " e8dccf76-8965-4289-bc86-d0a93a351ced\n\n";
        std::cerr << "Config file: ~/.pas/config.json\n";
        return 1;
    }

    std::string apiId = argv[1];

    // Load configuration from ~/.pas/config.json
    example::Config pasConfig;
    if (!example::loadConfig(apiId, pasConfig)) {
        std::cerr << "Error: Could not load configuration for API ID: " << apiId
                  << "\n\n";
        std::cerr << "Config file: ~/.pas/config.json\n";
        std::cerr << "Expected format:\n";
        std::cerr << "{\n";
        std::cerr << "  \"" << apiId << "\": {\n";
        std::cerr << "    \"client_secret\": \"...\",\n";
        std::cerr << "    \"customer\": \"...\",\n";
        std::cerr << "    \"gatekeeper\": \"...\",\n";
        std::cerr << "    \"server\": \"...\",\n";
        std::cerr << "    \"insecure\": \"true\"\n";
        std::cerr << "  }\n";
        std::cerr << "}\n";
        return 1;
    }

    std::cout << "Loaded configuration for API ID: " << apiId << "\n";

    // Step 1: Register logging callback
    std::cout << "=== Step 1: Registering logging callback ===\n";
    rssSetLogCallback(loggingCallback, nullptr);
    rssSetLogLevel(RSS_LOG_INFO);

    // Step 2: Authenticate with OAuth2
    std::cout << "\n=== Step 2: Authenticating with OAuth2 ===\n";
    std::cout << "Server: " << pasConfig.server << "\n";
    std::cout << "Customer: " << pasConfig.customer << "\n";
    std::cout << "Gatekeeper: " << pasConfig.gatekeeper << "\n";
    if (pasConfig.insecure) {
        std::cout << "WARNING: SSL verification disabled\n";
    }

    example::OAuth2Result authResult =
        example::authenticateOAuth2(pasConfig.server, pasConfig.clientId,
                                    pasConfig.clientSecret, pasConfig.insecure);

    if (!authResult.success) {
        std::cerr << "Authentication failed: " << authResult.errorMessage
                  << "\n";
        return 1;
    }

    std::cout << "Authentication successful!\n";

    if (!authResult.newSecret.empty()) {
        std::cout << "INFO: API secret has been rotated by server\n";
        std::cout << "New secret: " << authResult.newSecret << "\n";

        // Save the new secret to credentials file
        if (example::saveCredentials(pasConfig.clientId,
                                     authResult.newSecret)) {
            std::cout << "New secret saved successfully\n";
        } else {
            std::cerr << "WARNING: Failed to save new secret!\n";
        }
    }

    // Step 3: Get connection parameters (gatekeeper info and SSH key)
    std::cout << "\n=== Step 3: Getting Connection Parameters ===\n";

    example::ConnectionParams params = example::createConnection(
        pasConfig.server, authResult.accessToken, pasConfig.customer,
        pasConfig.gatekeeper, pasConfig.insecure);

    if (params.serverHost.empty() || params.privateKey.empty()) {
        std::cerr << "Failed to get connection parameters\n";
        return 1;
    }

    // Step 4: Generate launch file with additional configuration
    std::cout << "\n=== Step 4: Generating Launch File ===\n";
    std::string launchFileContent = example::generateLaunchFile(params);

    // Configuration Options - Modify these to customize Connection Manager
    // behavior
    std::stringstream configOptions;

    // Java Runtime: Use system Java instead of downloading
    configOptions << "scm.useInstalledJava=true\n";

    // IP Connect: Enable automatic IP address mapping
    configOptions << "disableIpConnect=false\n";
    configOptions << "scm.ipConnectMode=driverWithLegacyFallback\n";

    // Connection Mode: Connection protocol
    configOptions << "scm.scmConnectMode=default\n";

    // Security: Verify checksums of downloaded files
    configOptions << "enforceChecksum=true\n";

    // Updates: Allow automatic component upgrades
    configOptions << "pullUpgradePaths=true\n";

    // Logging: Enable debug output
    configOptions << "debugFlag=true\n";

    launchFileContent += configOptions.str();

    std::string tempLaunchFile =
        std::filesystem::temp_directory_path().string() +
        "/connection.securelinkcm";
    if (!example::writeLaunchFile(tempLaunchFile, launchFileContent)) {
        std::cerr << "Failed to write launch file\n";
        return 1;
    }

    std::cout << "Launch file written to: " << tempLaunchFile << "\n";

    // Step 5: Initialize Connection Manager
    std::cout << "\n=== Step 5: Initializing Connection Manager ===\n";

    ConnectionManagerConfig config;
    connectionManagerConfigInit(&config);

    strncpy(config.launchFile, tempLaunchFile.c_str(),
            RSS_CONFIG_STRING_LENGTH - 1);
    config.launchFile[RSS_CONFIG_STRING_LENGTH - 1] = '\0';

    auto stagingFolder =
        std::filesystem::temp_directory_path() / "librssconnect-staging";
    if (exists(stagingFolder)) {
        remove_all(stagingFolder);
    }

    std::filesystem::create_directories(stagingFolder);
    strncpy(config.stagingFolder, stagingFolder.string().c_str(),
            RSS_CONFIG_STRING_LENGTH - 1);
    config.stagingFolder[RSS_CONFIG_STRING_LENGTH - 1] = '\0';
    std::cout << "Staging folder: " << config.stagingFolder << '\n';

    // Step 6: Create, configure, and initialize
    std::cout << "\n=== Step 6: Setting Up Connection ===\n";

    std::cout << "Creating connection manager...\n";
    ConnectionManagerHandle handle = createConnectionManager(&config);

    if (!handle) {
        std::cerr << "Failed to create connection manager\n";
        return 1;
    }

    std::cout << "\nConfiguring connection manager...\n";
    RssErrorCode configResult = configureConnectionManager(handle);
    if (configResult != RSS_OK) {
        std::cerr << "Failed to configure connection manager (error code: "
                  << configResult << ")\n";

        destroyConnectionManager(handle);
        return 1;
    }

    std::cout << "Initializing connection manager...\n";
    RssErrorCode initResult = initializeConnectionManager(handle);
    if (initResult != RSS_OK) {
        std::cerr << "Failed to initialize connection manager (error code: "
                  << initResult << ")\n";

        destroyConnectionManager(handle);
        return 1;
    }

    // Step 7: Run connection manager in background thread
    std::cout << "\n=== Step 7: Running Connection Manager ===\n";
    std::cout << "Starting connection manager in background...\n";
    std::cout << "Connection manager will run until stopped\n";

    // Track if connection manager is still running
    std::atomic<bool> isRunning{true};

    // Start connection manager in background thread

    // Create message callbacks to detect SETUSER
    RssMessageCallbacks callbacks = createRssMessageCallbacks();
    rssMessageSetOnReceiveCallback(callbacks, onMessageReceived, nullptr);

    std::thread cmThread([handle, callbacks, &isRunning]() {
        RssErrorCode runResult = runConnectionManager(handle, callbacks);
        isRunning = false;
        if (runResult != RSS_OK) {
            std::cerr << "\n[CM Thread] Connection manager failed with error: "
                      << runResult << "\n";
        }
    });

    // Wait for connection manager to initialize and register with server
    // The CM needs to process INIT and SETUSER, and the server needs to
    // add the user to the CM's userList before v2/connection can find it
    std::cout << "Waiting for SETUSER response (CM registration)...\n";
    {
        std::unique_lock<std::mutex> lock(loggedInMutex);
        if (!loggedInCondition.wait_for(lock, std::chrono::seconds(30), [] {
                return receivedLoggedIn.load();
            })) {
            std::cerr << "Timeout waiting for SETUSER response!\n";
            stopConnectionManager(handle);
            cmThread.join();
            destroyRssMessageCallbacks(callbacks);
            destroyConnectionManager(handle);
            return 1;
        }
        std::cout << "CM registered! SETUSER response received.\n";
    }

    if (!isRunning) {
        std::cerr << "Connection manager stopped unexpectedly!\n";
        cmThread.join();
        destroyRssMessageCallbacks(callbacks);
        destroyConnectionManager(handle);
        return 1;
    }

    // Step 8: Call v2/connection API to initiate attach
    std::cout << "\n=== Step 8: Initiating Connection via API ===\n";
    std::cout << "Calling POST /v2/connection to trigger attach...\n";

    if (!example::initiateConnection(params)) {
        std::cerr << "WARNING: Failed to initiate connection via API\n";
        std::cerr
            << "You will see SETUSER but not ATTACHREQUEST/FORWARDL/MAPHOST\n";
    }

    std::cout << "\n[Main] Stopping connection manager...\n";
    stopConnectionManager(handle);

    // Wait for CM thread to finish
    cmThread.join();

    std::cout << "Connection manager stopped successfully\n";

    // Step 9: Cleanup
    std::cout << "\n=== Step 9: Cleaning Up ===\n";
    destroyRssMessageCallbacks(callbacks);
    destroyConnectionManager(handle);

    return 0;
}
