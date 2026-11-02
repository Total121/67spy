cmake_minimum_required(VERSION 3.16)
project(implant C)

set(CMAKE_C_STANDARD 11)

# ── Release flags ─────────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(
        /O2 /W4 /permissive-
        /GS             # stack protection
        /DNDEBUG
        /D_CRT_SECURE_NO_WARNINGS
    )
    add_link_options(/INCREMENTAL:NO /OPT:REF /OPT:ICF)
else()
    # MinGW cross-compile
    add_compile_options(
        -O2 -Wall -Wextra -Wno-unused-parameter
        -DNDEBUG
        -fstack-protector-strong
        -D_WIN32_WINNT=0x0601     # Windows 7+
        -DWINVER=0x0601
    )
    add_link_options(-Wl,--strip-all -Wl,--gc-sections)
endif()

# ── WIN32 GUI subsystem (no console window) ───────────────────────────────────
add_executable(implant WIN32 implant.c)

# ── Windows libraries ─────────────────────────────────────────────────────────
target_link_libraries(implant PRIVATE
    wininet
    bcrypt
    avicap32
    vfw32
    ws2_32
    shlwapi
    advapi32
    user32
    gdi32
)

# ── Strip symbols in Release ──────────────────────────────────────────────────
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT MSVC)
    add_custom_command(TARGET implant POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:implant>
        COMMENT "Stripping symbols"
    )
endif()
