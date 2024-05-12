cmake_minimum_required(VERSION 3.13)
project(msdelta-pa30 LANGUAGES C)

add_library(dump_lib 
	bitreader/bitreader.c
	bitreader/huffman.c
	getdeltainfo.c
	plzx/huffdec.c
	plzx/composite.c)

add_executable(dump dump.c)
target_link_libraries(dump dump_lib)
