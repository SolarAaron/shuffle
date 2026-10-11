// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef SHUFFLE_TERMINAL_PASSWORD_HPP
#define SHUFFLE_TERMINAL_PASSWORD_HPP

#include <string>

/** Reads one password line, suppressing terminal echo when stdin is interactive. */
bool readTerminalPassword(std::string& password);

#endif // SHUFFLE_TERMINAL_PASSWORD_HPP
