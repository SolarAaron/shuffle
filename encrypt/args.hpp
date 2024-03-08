#include <string>
#include <vector>

#ifndef SHUFFLE_ARGS_HPP
#define SHUFFLE_ARGS_HPP

class Args{
public:
    std::vector<std::string> file_names;
    std::string keyfile_name;
    bool use_keyfile;
    Args& parse(int argc, char** argv);
};

#endif //SHUFFLE_ARGS_HPP
