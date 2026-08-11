#pragma once

#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(ZETA_VAULT_BUILDING_LIBRARY)
#define ZETA_VAULT_API __declspec(dllexport)
#else
#define ZETA_VAULT_API __declspec(dllimport)
#endif
#else
#define ZETA_VAULT_API __attribute__((visibility("default")))
#endif
