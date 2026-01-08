cmake_minimum_required(VERSION 3.15)
project(
  librssconnect-reference-app
  VERSION 1.0.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Check if we're being built as part of the main librssconnect project
if(TARGET rssconnect_shared)
  message(
    STATUS
      "Building reference app as part of librssconnect project (using build tree)"
  )

  add_executable(reference_app main.cpp oauth_helper.cpp oauth_helper.h)

  # Link against shared library (demonstrates typical customer usage) Use
  # PkgConfig::CURL if available (from pkg-config), otherwise CURL::libcurl
  # (from FindCURL)
  set(CURL_TARGET "CURL::libcurl")
  if(TARGET PkgConfig::CURL)
    set(CURL_TARGET "PkgConfig::CURL")
  endif()

  target_link_libraries(reference_app PRIVATE rssconnect_shared ${CURL_TARGET}
                                              Threads::Threads)

  target_include_directories(reference_app PRIVATE ${CMAKE_SOURCE_DIR}/include)

  if(WIN32)
    add_custom_command(
      TARGET reference_app
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              $<TARGET_FILE:rssconnect_shared> $<TARGET_FILE_DIR:reference_app>
      COMMENT "Copying rssconnect.dll to reference_app directory")
  endif()
else()
  # We're being built standalone - find dependencies
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(CURL QUIET libcurl IMPORTED_TARGET)
  endif()

  if(NOT CURL_FOUND)
    find_package(CURL REQUIRED)
  endif()
  find_package(Threads REQUIRED)

  # Find installed librssconnect
  find_package(librssconnect CONFIG QUIET)

  if(librssconnect_FOUND)
    message(STATUS "Found librssconnect via find_package()")
    add_executable(reference_app main.cpp oauth_helper.cpp oauth_helper.h)

    # Use PkgConfig::CURL if available (from pkg-config), otherwise
    # CURL::libcurl (from FindCURL)
    set(CURL_TARGET "CURL::libcurl")
    if(TARGET PkgConfig::CURL)
      set(CURL_TARGET "PkgConfig::CURL")
    endif()

    target_link_libraries(reference_app PRIVATE librssconnect::rssconnect_shared
                                                ${CURL_TARGET} Threads::Threads)
  else()
    # Fallback to legacy LIBRSSCONNECT_DIR method for backward compatibility
    message(
      STATUS
        "librssconnect not found via find_package(), trying legacy LIBRSSCONNECT_DIR method"
    )

    if(DEFINED LIBRSSCONNECT_DIR)
      set(LIBRSSCONNECT_INCLUDE_DIR "${LIBRSSCONNECT_DIR}/include")
      set(LIBRSSCONNECT_LIB_DIR "${LIBRSSCONNECT_DIR}/lib")
    else()
      # Try to find in standard locations
      find_path(
        LIBRSSCONNECT_INCLUDE_DIR
        NAMES RssConnectionManager.h
        PATHS /usr/local/include /usr/include)
      find_library(
        LIBRSSCONNECT_LIBRARY
        NAMES rssconnect ConnectionManager
        PATHS /usr/local/lib /usr/lib)
    endif()

    if(NOT LIBRSSCONNECT_INCLUDE_DIR)
      message(
        FATAL_ERROR
          "librssconnect not found. Please use one of the following methods:\n"
          "  1. Modern CMake (recommended): cmake -DCMAKE_PREFIX_PATH=/path/to/librssconnect/install\n"
          "  2. Legacy method: cmake -DLIBRSSCONNECT_DIR=/path/to/librssconnect/install\n"
          "  3. Install librssconnect to a standard system location")
    endif()

    add_executable(reference_app main.cpp oauth_helper.cpp oauth_helper.h)
    target_include_directories(reference_app
                               PRIVATE ${LIBRSSCONNECT_INCLUDE_DIR})

    # Use PkgConfig::CURL if available (from pkg-config), otherwise
    # CURL::libcurl (from FindCURL)
    set(CURL_TARGET "CURL::libcurl")
    if(TARGET PkgConfig::CURL)
      set(CURL_TARGET "PkgConfig::CURL")
    endif()

    if(LIBRSSCONNECT_LIBRARY)
      target_link_libraries(
        reference_app PRIVATE ${LIBRSSCONNECT_LIBRARY} ${CURL_TARGET}
                              Threads::Threads)
    elseif(LIBRSSCONNECT_LIB_DIR)
      if(WIN32)
        target_link_libraries(
          reference_app PRIVATE ${LIBRSSCONNECT_LIB_DIR}/rssconnect.lib
                                ${CURL_TARGET} Threads::Threads)
      elseif(APPLE)
        target_link_libraries(
          reference_app PRIVATE ${LIBRSSCONNECT_LIB_DIR}/librssconnect.dylib
                                ${CURL_TARGET} Threads::Threads)
      else()
        target_link_libraries(
          reference_app PRIVATE ${LIBRSSCONNECT_LIB_DIR}/librssconnect.so
                                ${CURL_TARGET} Threads::Threads)
      endif()
    else()
      message(
        FATAL_ERROR
          "librssconnect library not found. Set LIBRSSCONNECT_DIR or install librssconnect."
      )
    endif()
  endif()
endif()

# Platform-specific settings
if(WIN32)
  target_compile_definitions(reference_app PRIVATE _WIN32_WINNT=0x0601)
elseif(APPLE)
  target_compile_options(reference_app PRIVATE -Wall -Wextra)
else()
  target_compile_options(reference_app PRIVATE -Wall -Wextra)
  target_link_libraries(reference_app PRIVATE dl)
endif()

# Install README
install(FILES README.md DESTINATION share/doc/librssconnect-reference-app)
