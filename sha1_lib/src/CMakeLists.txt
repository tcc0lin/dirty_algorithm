SET(CMAKE_CXX_FLAGS " -g -Wall -o2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
SET(sha1_lib_path ${PROJECT_SOURCE_DIR}/lib)
SET(sha1_src_path ${PROJECT_SOURCE_DIR}/src)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

AUX_SOURCE_DIRECTORY(${sha1_src_path} X_SRC)
ADD_LIBRARY(sha1 STATIC ${X_SRC})

SET_TARGET_PROPERTIES(sha1 PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${sha1_lib_path}")
