// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef SHUFFLE_TERMINAL_PASSWORD_HPP
#define SHUFFLE_TERMINAL_PASSWORD_HPP

#include <string>

/**
 * Reads one password line into `password`.
 *
 * Terminal echo is disabled while reading from an interactive standard input
 * and restored before return. Returns `true` after a complete line is read and
 * `false` on end-of-file or an input error.
 */
bool readTerminalPassword(std::string& password);

#endif // SHUFFLE_TERMINAL_PASSWORD_HPP
