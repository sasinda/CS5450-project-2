cmake_minimum_required(VERSION 3.6)
project(lisod)

set(CMAKE_C_STANDARD 99)

set(REC_FILES gbn.h gbn.c receiver.c)
set(SEN_FILES gbn.h gbn.c sender.c)
set(TST_FILES gbn.h gbn.c tester.c)

add_executable(receiver ${REC_FILES})
add_executable(sender ${SEN_FILES})
add_executable(tst ${TST_FILES})