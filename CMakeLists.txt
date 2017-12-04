cmake_minimum_required (VERSION 2.6)
project (Whiteboard)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)


SET(CT_SRC_LIST ${CT_SRC_LIST} control.c)
SET(CT_SRC_LIST ${CT_SRC_LIST} contrib/cJSON.c)
IF(WIN32)
SET(CT_SRC_LIST ${CT_SRC_LIST} contrib/getopt_long.c)
ENDIF(WIN32)

SET(INC_LIST contrib)
SET(SRC_LIST ${SRC_LIST} net.cpp
		whiteboard.cpp)

SET(SRC_LIST ${SRC_LIST} contrib/bcode.cpp
		contrib/cJSON.c
		contrib/md5.c
		contrib/sha1.c
		contrib/sqlite3.c)
IF(WIN32)
SET(SRC_LIST ${SRC_LIST} contrib/getopt_long.c)
ENDIF(WIN32)

INCLUDE_DIRECTORIES(${INC_LIST})
ADD_EXECUTABLE(control ${CT_SRC_LIST})
ADD_EXECUTABLE(server ${SRC_LIST})

if(CMAKE_COMPILER_IS_GNUCXX)
	list( APPEND CMAKE_CXX_FLAGS "-std=c++0x -D_FORCE_INLINES ${CMAKE_CXX_FLAGS} -g -ftest-coverage -fprofile-arcs")
	find_package(Threads REQUIRED)
	if(THREADS_HAVE_PTHREAD_ARG)
	target_compile_options(server PUBLIC "-pthread -lsqlite3")
	endif()
	
	if(CMAKE_THREAD_LIBS_INIT)
	target_link_libraries(server "${CMAKE_THREAD_LIBS_INIT} -ldl")
	endif()
endif()

add_custom_command(TARGET server POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy_directory
                   ${CMAKE_SOURCE_DIR}/config $<TARGET_FILE_DIR:server>)
