add_executable(zeta_vault_unit_tests
  cpp_wrapper_tests.cpp
  protocol_tests.cpp
  vault_store_tests.cpp)
target_include_directories(zeta_vault_unit_tests PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(zeta_vault_unit_tests PRIVATE
  GTest::gtest_main
  zeta_vault::cpp
  zeta_vault_protocol
  zeta_vault_storage
  ${ZETA_VAULT_SODIUM_TARGET})
zeta_vault_enable_warnings(zeta_vault_unit_tests)

include(GoogleTest)
gtest_discover_tests(zeta_vault_unit_tests)
