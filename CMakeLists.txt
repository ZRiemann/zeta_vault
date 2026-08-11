cmake_minimum_required(VERSION 3.20)

set(ZETA_VAULT_VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
if(NOT EXISTS "${ZETA_VAULT_VERSION_FILE}")
  message(FATAL_ERROR
          "zeta_vault VERSION file not found: ${ZETA_VAULT_VERSION_FILE}")
endif()

file(STRINGS "${ZETA_VAULT_VERSION_FILE}" ZETA_VAULT_VERSION_RAW
     LIMIT_COUNT 1)
string(STRIP "${ZETA_VAULT_VERSION_RAW}" ZETA_VAULT_VERSION_RAW)
if(NOT ZETA_VAULT_VERSION_RAW MATCHES
   "^v([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
  message(FATAL_ERROR
          "Invalid zeta_vault VERSION value: ${ZETA_VAULT_VERSION_RAW}\n"
          "Expected format: vX.Y.Z, for example v0.1.0.")
endif()
set(ZETA_VAULT_PROJECT_VERSION
    "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}")

project(zeta_vault VERSION ${ZETA_VAULT_PROJECT_VERSION} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

option(ZETA_VAULT_BUILD_TESTS "Build zeta_vault tests" ON)
option(ZETA_VAULT_BUILD_EXAMPLES "Build zeta_vault examples" ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR
          "zeta_vault currently requires Linux peer-credential support")
endif()

set(ZETA_CMAKE_UTIL_DIR "" CACHE PATH "Path to zeta_forge/cmake_util")
if(NOT ZETA_CMAKE_UTIL_DIR AND DEFINED ENV{ZETAX_ROOT})
  set(_zeta_cmake_util_from_workspace
      "$ENV{ZETAX_ROOT}/zeta_forge/cmake_util")
  if(EXISTS "${_zeta_cmake_util_from_workspace}/common.cmake")
    set(ZETA_CMAKE_UTIL_DIR "${_zeta_cmake_util_from_workspace}"
        CACHE PATH "Path to zeta_forge/cmake_util" FORCE)
  endif()
endif()
if(ZETA_CMAKE_UTIL_DIR AND EXISTS "${ZETA_CMAKE_UTIL_DIR}/common.cmake")
  include("${ZETA_CMAKE_UTIL_DIR}/common.cmake")
endif()

set(ZETA_DEPS_CMAKE_DIR "" CACHE PATH
    "Path to installed zeta_forge deps CMake package files")
if(ZETA_DEPS_CMAKE_DIR)
  list(PREPEND CMAKE_PREFIX_PATH "${ZETA_DEPS_CMAKE_DIR}")
endif()

find_package(Threads REQUIRED)
find_package(zpp 0.12 CONFIG REQUIRED)

find_package(sodium CONFIG QUIET)
find_package(libsodium CONFIG QUIET)
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET sodium::sodium)
  set(ZETA_VAULT_SODIUM_TARGET sodium::sodium)
elseif(TARGET libsodium::libsodium)
  set(ZETA_VAULT_SODIUM_TARGET libsodium::libsodium)
elseif(TARGET unofficial-sodium::sodium)
  set(ZETA_VAULT_SODIUM_TARGET unofficial-sodium::sodium)
else()
  message(FATAL_ERROR
          "libsodium target not found. Install zeta_forge deps first.")
endif()

function(zeta_vault_enable_warnings target)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
  elseif(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive-)
  endif()
endfunction()

add_subdirectory(src)

if(ZETA_VAULT_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(ZETA_VAULT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/zeta_vaultConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/zeta_vaultConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/zeta_vaultConfig.cmake"
  INSTALL_DESTINATION lib/cmake/zeta_vault)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/zeta_vaultConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/zeta_vaultConfigVersion.cmake"
  DESTINATION lib/cmake/zeta_vault)
install(EXPORT zeta_vaultTargets
  NAMESPACE zeta_vault::
  FILE zeta_vaultTargets.cmake
  DESTINATION lib/cmake/zeta_vault)
