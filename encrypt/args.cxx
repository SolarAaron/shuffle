#include "args.hpp"

Args& Args::parse(int argc, char** argv){
    bool nextIsKey = false;
    for(int arg = 1; arg < argc; arg++){
        if(std::string(argv[arg]) == "-k"){
            nextIsKey = true;
            use_keyfile = true;
        }else if(nextIsKey){
            keyfile_name = std::string(argv[arg]);
            nextIsKey = false;
        }else{
            file_names.emplace_back(argv[arg]);
        }
    }

    return *this;
}

