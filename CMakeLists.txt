cmake_minimum_required(VERSION 3.19)
project(acars_crypt C)

set(CMAKE_C_STANDARD 99)

AUX_SOURCE_DIRECTORY(. SRC_LIST) #把当前目录(.)下所有源代码文件和头文件加入变量SRC_LIST
add_executable(acarscrypto Crypto.c Crypto.h)
add_library(acarscrypt SHARED ${SRC_LIST})

set_target_properties(acarscrypt PROPERTIES output_name "acarscrypt")
TARGET_LINK_LIBRARIES(acarscrypto LINK_PUBLIC gmssl)
TARGET_LINK_LIBRARIES(acarscrypt LINK_PUBLIC gmssl)
