add_library(zeta_vault_protocol STATIC
  protocol/protocol.cpp)
add_library(zeta_vault::protocol ALIAS zeta_vault_protocol)
target_include_directories(zeta_vault_protocol
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(zeta_vault_protocol PUBLIC zpp::zpp)
zeta_vault_enable_warnings(zeta_vault_protocol)

add_library(zeta_vault_common STATIC
  common/io.cpp)
target_include_directories(zeta_vault_common
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(zeta_vault_common PUBLIC Threads::Threads)
zeta_vault_enable_warnings(zeta_vault_common)

add_library(zeta_vault_storage STATIC
  storage/vault_store.cpp)
target_include_directories(zeta_vault_storage
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(zeta_vault_storage
  PUBLIC
    zpp::zpp
    ${ZETA_VAULT_SODIUM_TARGET}
    zeta_vault_common)
zeta_vault_enable_warnings(zeta_vault_storage)

add_library(zeta_vault_c SHARED
  client/client.cpp)
add_library(zeta_vault::c ALIAS zeta_vault_c)
set_target_properties(zeta_vault_c PROPERTIES
  EXPORT_NAME c
  OUTPUT_NAME zeta_vault
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR})
target_compile_definitions(zeta_vault_c PRIVATE
  _GNU_SOURCE
  ZETA_VAULT_BUILDING_LIBRARY)
target_include_directories(zeta_vault_c
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(zeta_vault_c
  PRIVATE
    zeta_vault_protocol
    zeta_vault_common
    ${ZETA_VAULT_SODIUM_TARGET})
zeta_vault_enable_warnings(zeta_vault_c)

add_library(zeta_vault_cpp INTERFACE)
add_library(zeta_vault::cpp ALIAS zeta_vault_cpp)
set_target_properties(zeta_vault_cpp PROPERTIES EXPORT_NAME cpp)
target_include_directories(zeta_vault_cpp INTERFACE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_link_libraries(zeta_vault_cpp INTERFACE zeta_vault_c)

add_library(zeta_vault_server_core STATIC
  server/server.cpp)
target_compile_definitions(zeta_vault_server_core PRIVATE _GNU_SOURCE)
target_include_directories(zeta_vault_server_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(zeta_vault_server_core
  PUBLIC
    zeta_vault_protocol
    zeta_vault_common
    zeta_vault_storage
    ${ZETA_VAULT_SODIUM_TARGET})
zeta_vault_enable_warnings(zeta_vault_server_core)

add_executable(zeta_vault_server
  server/main.cpp
  server/password_prompt.cpp)
target_compile_definitions(zeta_vault_server PRIVATE _GNU_SOURCE)
target_include_directories(zeta_vault_server PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(zeta_vault_server PRIVATE zeta_vault_server_core)
zeta_vault_enable_warnings(zeta_vault_server)

add_library(zeta_vault_ctl_core STATIC
  ctl/ctl.cpp)
target_compile_definitions(zeta_vault_ctl_core PRIVATE _GNU_SOURCE)
target_include_directories(zeta_vault_ctl_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(zeta_vault_ctl_core
  PUBLIC
    zeta_vault::cpp
  PRIVATE
    ${ZETA_VAULT_SODIUM_TARGET})
zeta_vault_enable_warnings(zeta_vault_ctl_core)

add_executable(zeta_vault_ctl
  ctl/main.cpp)
target_include_directories(zeta_vault_ctl PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(zeta_vault_ctl PRIVATE zeta_vault_ctl_core)
set_target_properties(zeta_vault_ctl PROPERTIES
  INSTALL_RPATH "$ORIGIN/../lib")
zeta_vault_enable_warnings(zeta_vault_ctl)

install(TARGETS zeta_vault_c zeta_vault_cpp
  EXPORT zeta_vaultTargets
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  INCLUDES DESTINATION include)
install(TARGETS zeta_vault_server zeta_vault_ctl RUNTIME DESTINATION bin)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ DESTINATION include)
