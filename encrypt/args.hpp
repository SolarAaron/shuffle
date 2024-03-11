#include <string>
#include <vector>

#ifndef SHUFFLE_ARGS_HPP
#define SHUFFLE_ARGS_HPP

class Args{
public:
    std::vector<std::string> file_names;
    std::vector<std::string> keyfile_names;
    size_t iterations;
    size_t verbosity;
    bool use_keyfile;
    Args();
    Args& parse(int argc, char** argv);
};

#endif //SHUFFLE_ARGS_HPP
