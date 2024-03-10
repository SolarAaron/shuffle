#include "args.hpp"

Args& Args::parse(int argc, char** argv){
    bool nextIsKey = false, nextIsIter = false;
    for(int arg = 1; arg < argc; arg++){
        if(std::string(argv[arg]) == "-k"){
            nextIsKey = true;
            use_keyfile = true;
        } else if(std::string(argv[arg]) == "-i") {
            nextIsIter = true;
        }else if(nextIsKey){
            keyfile_names.emplace_back(argv[arg]);
            nextIsKey = false;
        } else if(nextIsIter) {
            iterations = std::stoull(argv[arg]);
            nextIsIter = false;
        }else{
            file_names.emplace_back(argv[arg]);
        }
    }

    return *this;
}

