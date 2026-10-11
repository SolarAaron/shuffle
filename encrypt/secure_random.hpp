// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef SHUFFLE_SECURE_RANDOM_HPP
#define SHUFFLE_SECURE_RANDOM_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

inline void secureRandomBytes(uint8_t* destination, size_t length) {
    if(length != 0 && destination == nullptr) {
        throw std::invalid_argument("secureRandomBytes requires a destination buffer");
    }
    if(length == 0) return;

#ifdef _WIN32
    // Resolve the system RNG export dynamically to avoid an extra import library.
    using SystemRandomFunction = BOOLEAN (WINAPI *)(PVOID, ULONG);
    struct ModuleGuard {
        HMODULE module;
        ~ModuleGuard() { if(module != nullptr) FreeLibrary(module); }
    };

    ModuleGuard advapi32{LoadLibraryW(L"advapi32.dll")};
    if(advapi32.module == nullptr) {
        throw std::runtime_error("unable to load the Windows system random source");
    }
    const auto systemRandom = reinterpret_cast<SystemRandomFunction>(
        GetProcAddress(advapi32.module, "SystemFunction036"));
    if(systemRandom == nullptr) {
        throw std::runtime_error("Windows system random source is unavailable");
    }

    size_t offset = 0;
    while(offset < length) {
        const size_t count = std::min(length - offset,
                                      static_cast<size_t>(std::numeric_limits<ULONG>::max()));
        if(!systemRandom(destination + offset, static_cast<ULONG>(count))) {
            throw std::runtime_error("Windows system random generator failed");
        }
        offset += count;
    }
#else
    const int source = open("/dev/urandom", O_RDONLY);
    if(source < 0) throw std::runtime_error("unable to open the system random source");

    size_t offset = 0;
    while(offset < length) {
        const size_t requested = std::min(length - offset, static_cast<size_t>(4096));
        const ssize_t count = read(source, destination + offset, requested);
        if(count < 0 && errno == EINTR) continue;
        if(count <= 0) {
            close(source);
            throw std::runtime_error("unable to read the system random source");
        }
        offset += static_cast<size_t>(count);
    }

    if(close(source) != 0) throw std::runtime_error("unable to close the system random source");
#endif
}

#endif // SHUFFLE_SECURE_RANDOM_HPP
