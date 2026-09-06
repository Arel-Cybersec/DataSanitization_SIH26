cmake_minimum_required(VERSION 3.16)
project(erasecure VERSION 0.1.0 LANGUAGES C)

# ─── Language standard ────────────────────────────────────────
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ─── Output directories ───────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ─── Compiler warning flags ───────────────────────────────────
set(ERASECURE_WARN_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
    -Wformat=2
    -Wno-unused-parameter   # permit stub functions with unused args
)

# ─── Security hardening flags ─────────────────────────────────
set(ERASECURE_HARDEN_FLAGS
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# ─── Sanitizer flags (Debug builds only) ──────────────────────
set(ERASECURE_SANITIZER_FLAGS
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
)

# ─── Required dependencies ────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# SQLite3: try pkg-config then manual search
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SQLITE3 sqlite3)
endif()

if(NOT SQLITE3_FOUND)
    find_library(SQLITE3_LIBRARIES NAMES sqlite3)
    find_path(SQLITE3_INCLUDE_DIRS NAMES sqlite3.h)
    if(SQLITE3_LIBRARIES AND SQLITE3_INCLUDE_DIRS)
        set(SQLITE3_FOUND TRUE)
    endif()
endif()

if(NOT SQLITE3_FOUND)
    message(FATAL_ERROR
        "SQLite3 not found. Install: sudo apt-get install libsqlite3-dev")
endif()

message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "SQLite3: ${SQLITE3_LIBRARIES}")

# ═══════════════════════════════════════════════════════════════
# erasecure_core  —  static library containing all modules
# ═══════════════════════════════════════════════════════════════
add_library(erasecure_core STATIC
    src/common/constants.c
    src/common/error.c

    src/device/device.c
    src/device/device_detect.c
    src/device/device_info.c

    src/sanitization/block_erase.c
    src/sanitization/crypto_erase.c
    src/sanitization/verification.c
    src/sanitization/sanitizer.c

    src/hdd/hdd_sanitizer.c
    src/ssd/ssd_sanitizer.c
    src/portable/portable_sanitizer.c

    src/crypto/hash.c
    src/crypto/key_management.c

    src/audit/audit.c
    src/audit/audit_log.c
)

target_include_directories(erasecure_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIRS}
)

target_compile_options(erasecure_core PRIVATE
    ${ERASECURE_WARN_FLAGS}
    ${ERASECURE_HARDEN_FLAGS}
    $<$<CONFIG:Debug>:${ERASECURE_SANITIZER_FLAGS}>
)

target_link_libraries(erasecure_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIBRARIES}
    Threads::Threads
)

target_link_options(erasecure_core PUBLIC
    $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)

# ═══════════════════════════════════════════════════════════════
# erasecure_cli  —  command-line executable
# ═══════════════════════════════════════════════════════════════
add_executable(erasecure_cli
    src/ui/cli.c
    src/main.c
)

target_include_directories(erasecure_cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(erasecure_cli PRIVATE
    ${ERASECURE_WARN_FLAGS}
    ${ERASECURE_HARDEN_FLAGS}
    $<$<CONFIG:Debug>:${ERASECURE_SANITIZER_FLAGS}>
)

target_link_libraries(erasecure_cli PRIVATE erasecure_core)

set_target_properties(erasecure_cli PROPERTIES OUTPUT_NAME erasecure)

# ═══════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════
enable_testing()

# Helper macro to define a test binary
macro(erasecure_add_test test_name test_src)
    add_executable(${test_name} ${test_src})
    target_include_directories(${test_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(${test_name} PRIVATE
        ${ERASECURE_WARN_FLAGS}
        $<$<CONFIG:Debug>:${ERASECURE_SANITIZER_FLAGS}>
    )
    target_link_libraries(${test_name} PRIVATE erasecure_core)
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endmacro()

erasecure_add_test(device_tests       tests/device_tests.c)
erasecure_add_test(block_erase_tests  tests/block_erase_tests.c)
erasecure_add_test(crypto_erase_tests tests/crypto_erase_tests.c)
erasecure_add_test(verification_tests tests/verification_tests.c)

# ═══════════════════════════════════════════════════════════════
# Optional: GTK GUI (future)
# ═══════════════════════════════════════════════════════════════
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(GTK3 QUIET gtk+-3.0)
    if(GTK3_FOUND)
        message(STATUS "GTK3 found — GUI target can be added in future phase")
        # Future:
        # add_executable(erasecure_gui src/gui/main_window.c ...)
        # target_link_libraries(erasecure_gui PRIVATE erasecure_core ${GTK3_LIBRARIES})
    else()
        message(STATUS "GTK3 not found — GUI target skipped (CLI still builds)")
    endif()
endif()

# ─── Summary ──────────────────────────────────────────────────
message(STATUS "")
message(STATUS "EraseCure build configuration:")
message(STATUS "  Version     : ${PROJECT_VERSION}")
message(STATUS "  C standard  : C${CMAKE_C_STANDARD}")
message(STATUS "  Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Targets     : erasecure_core (static), erasecure (CLI), tests")
message(STATUS "")
message(STATUS "  Build:  cmake --build . --parallel")
message(STATUS "  Tests:  ctest --output-on-failure")
message(STATUS "")
