// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "args.hpp"

Args& Args::parse(int argc, char** argv){
    bool nextIsKey = false, nextIsIter = false;
    for(int arg = 1; arg < argc; arg++){
        if(std::string(argv[arg]) == "-k"){
            nextIsKey = true;
            useKeyfile = true;
        } else if(std::string(argv[arg]) == "-i") {
            nextIsIter = true;
        } else if(std::string(argv[arg]) == "-v") {
            verbosity++;
        }else if(nextIsKey){
            keyfileNames.emplace_back(argv[arg]);
            nextIsKey = false;
        } else if(nextIsIter) {
            iterations = std::stoull(argv[arg]);
            nextIsIter = false;
        }else{
            fileNames.emplace_back(argv[arg]);
        }
    }

    return *this;
}

Args::Args(): fileNames(), keyfileNames(), iterations(0), verbosity(0), useKeyfile(false) {
}
