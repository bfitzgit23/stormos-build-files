# Install script for directory: /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "None")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "0")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/include/compiz/core/action.h;/usr/include/compiz/core/atoms.h;/usr/include/compiz/core/configurerequestbuffer.h;/usr/include/compiz/core/core.h;/usr/include/compiz/core/countedlist.h;/usr/include/compiz/core/global.h;/usr/include/compiz/core/icon.h;/usr/include/compiz/core/logmessage.h;/usr/include/compiz/core/match.h;/usr/include/compiz/core/modifierhandler.h;/usr/include/compiz/core/option.h;/usr/include/compiz/core/output.h;/usr/include/compiz/core/plugin.h;/usr/include/compiz/core/propertywriter.h;/usr/include/compiz/core/privateunion.h;/usr/include/compiz/core/screen.h;/usr/include/compiz/core/session.h;/usr/include/compiz/core/size.h;/usr/include/compiz/core/string.h;/usr/include/compiz/core/templates.h;/usr/include/compiz/core/window.h;/usr/include/compiz/core/wrapsystem.h;/usr/include/compiz/core/abiversion.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/include/compiz/core" TYPE FILE FILES
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/action.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/atoms.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/configurerequestbuffer.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/core.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/countedlist.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/global.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/icon.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/logmessage.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/match.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/modifierhandler.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/option.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/output.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/plugin.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/propertywriter.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/privateunion.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/screen.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/session.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/size.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/string.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/templates.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/window.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/wrapsystem.h"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/include/core/abiversion.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/include/core/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
