cmake_minimum_required( VERSION 3.19 )

if( NOT DEFINED LIBRARY_TYPE )
  message( FATAL_ERROR "You must set the variable LIBRARY_TYPE to either SHARED or STATIC." )
endif()

set( LIBRARY_NAME Bento4 )

project( ${LIBRARY_NAME} CXX )

set( CMAKE_INCLUDE_CURRENT_DIR ON )
set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )
set( CMAKE_CXX_EXTENSIONS OFF )

if( UNIX OR APPLE )
  set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4.2 -maes" )
endif()

if( WIN32 AND ${LIBRARY_TYPE} MATCHES "SHARED" )
  set( CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS True )
endif()

include_directories( include )

find_package( Qt5 REQUIRED COMPONENTS Core )

file( GLOB SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.cpp ${PROJECT_SOURCE_DIR}/src/*.h )

set_property( DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${LIBRARY_NAME} )

add_library( ${LIBRARY_NAME} ${LIBRARY_TYPE} ${SRC_FILES} )

target_link_libraries( ${LIBRARY_NAME} PRIVATE Qt5::Core )

target_include_directories( ${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include )
