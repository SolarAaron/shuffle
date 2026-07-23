// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef SHUFFLE_ARGS_HPP
#define SHUFFLE_ARGS_HPP

#include <cstddef>
#include <string>
#include <vector>

/** Parsed command-line options shared by the shuffle executables. */
class Args {
public:
    /** Input file names in command-line order. */
    std::vector<std::string> fileNames;
    /** Key-file names in command-line order. */
    std::vector<std::string> keyfileNames;
    /** Requested PBKDF iteration count, or zero to use the variant default. */
    std::size_t iterations;
    /** Number of verbosity flags supplied by the user. */
    std::size_t verbosity;
    /** Whether keys are read from files instead of the terminal. */
    bool useKeyfile;

    /** Constructs options with their command-line defaults. */
    Args();
    /** Parses `argv`, updates the stored options, and returns `*this`. */
    Args& parse(int argc, char** argv);
};

#endif // SHUFFLE_ARGS_HPP
