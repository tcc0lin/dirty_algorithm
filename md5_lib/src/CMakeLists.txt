SET(CMAKE_CXX_FLAGS " -g -Wall -o2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
SET(md5_lib_path ${PROJECT_SOURCE_DIR}/lib)
SET(md5_src_path ${PROJECT_SOURCE_DIR}/src)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

AUX_SOURCE_DIRECTORY(${md5_src_path} X_SRC)
ADD_LIBRARY(md5 STATIC ${X_SRC})

SET_TARGET_PROPERTIES(md5 PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${md5_lib_path}")
