// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "terminal_password.hpp"

#include <iostream>

#ifdef _WIN32
#include <conio.h>
#include <cstdio>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {
#ifndef _WIN32
    class EchoGuard {
    public:
        EchoGuard() {
            if(!isatty(STDIN_FILENO)) return;
            interactive_ = true;
            if(tcgetattr(STDIN_FILENO, &original_) != 0) return;
            termios hidden = original_;
            hidden.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHONL));
            active_ = tcsetattr(STDIN_FILENO, TCSANOW, &hidden) == 0;
        }

        ~EchoGuard() {
            if(active_) tcsetattr(STDIN_FILENO, TCSANOW, &original_);
        }

        bool active() const noexcept { return active_; }
        bool interactive() const noexcept { return interactive_; }

    private:
        termios original_{};
        bool active_ = false;
        bool interactive_ = false;
    };
#endif
}

bool readTerminalPassword(std::string& password) {
    password.clear();

#ifdef _WIN32
    if(!_isatty(_fileno(stdin))) return static_cast<bool>(std::getline(std::cin, password));

    for(;;) {
        const int input = _getch();
        if(input == '\r' || input == '\n') {
            std::cout << std::endl;
            return true;
        }
        if(input == EOF || input == 3 || input == 26) {
            std::cout << std::endl;
            return false;
        }
        if(input == '\b' || input == 127) {
            if(!password.empty()) password.pop_back();
            continue;
        }
        if(input == 0 || input == 0xe0) {
            (void) _getch();
            continue;
        }
        password.push_back(static_cast<char>(input));
    }
#else
    EchoGuard guard;
    if(guard.interactive() && !guard.active()) return false;
    const bool result = static_cast<bool>(std::getline(std::cin, password));
    if(guard.active()) std::cout << std::endl;
    return result;
#endif
}
