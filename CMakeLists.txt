cmake_minimum_required(VERSION 3.14)

project(mod_sndmem)

include_directories(/usr/local/freeswitch/include/freeswitch)
# include_directories(/usr/include/apr-1.0)

add_library(mod_sndmem SHARED
        mod_sndmem.cpp
)
