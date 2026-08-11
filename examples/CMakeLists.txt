add_executable(zeta_vault_c_example c_client.c)
target_link_libraries(zeta_vault_c_example PRIVATE zeta_vault::c)
