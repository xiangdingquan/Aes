# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

cmake_minimum_required(VERSION 3.4.1)

add_library( # Sets the name of the library.
        encrypt

        SHARED

        src/main/cpp/encrypt.cpp
        src/main/cpp/base64.h
        src/main/cpp/base64.c
        src/main/cpp/aes.h
        src/main/cpp/aes.c)

find_library( # Sets the name of the path variable.
        log-lib

        log )

target_link_libraries( # Specifies the target library.
        encrypt

        ${log-lib} )