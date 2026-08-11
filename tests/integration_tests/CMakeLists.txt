add_executable(zeta_vault_integration_tests
  ctl_tests.cpp
  server_client_tests.cpp)
target_compile_definitions(zeta_vault_integration_tests PRIVATE _GNU_SOURCE)
target_include_directories(zeta_vault_integration_tests PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(zeta_vault_integration_tests PRIVATE
  GTest::gtest_main
  zeta_vault::c
  zeta_vault_ctl_core
  zeta_vault_server_core)
zeta_vault_enable_warnings(zeta_vault_integration_tests)

include(GoogleTest)
gtest_discover_tests(zeta_vault_integration_tests)
