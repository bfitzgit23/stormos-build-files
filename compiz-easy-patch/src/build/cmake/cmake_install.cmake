# Install script for directory: /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake

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
   "/usr/share/compiz/cmake/CompizCommon.cmake;/usr/share/compiz/cmake/CompizPlugin.cmake;/usr/share/compiz/cmake/CompizPackage.cmake;/usr/share/compiz/cmake/CompizBcop.cmake;/usr/share/compiz/cmake/copy_file_install_user_env.cmake;/usr/share/compiz/cmake/recompile_gsettings_schemas_in_dir_user_env.cmake;/usr/share/compiz/cmake/CompizDefaults.cmake;/usr/share/compiz/cmake/CompizGSettings.cmake")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/share/compiz/cmake" TYPE FILE FILES
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/CompizCommon.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/CompizPlugin.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/CompizPackage.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/CompizBcop.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/copy_file_install_user_env.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/recompile_gsettings_schemas_in_dir_user_env.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/cmake/CompizDefaults.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/CompizGSettings.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/share/compiz/cmake/plugin_extensions/CompizGenInstallData.cmake;/usr/share/compiz/cmake/plugin_extensions/CompizGenInstallImages.cmake;/usr/share/compiz/cmake/plugin_extensions/CompizOpenGLFixups.cmake;/usr/share/compiz/cmake/plugin_extensions/CompizGenGSettings.cmake")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/share/compiz/cmake/plugin_extensions" TYPE FILE FILES
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/plugin_extensions/CompizGenInstallData.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/plugin_extensions/CompizGenInstallImages.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/plugin_extensions/CompizOpenGLFixups.cmake"
    "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/plugin_extensions/CompizGenGSettings.cmake"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/cmake/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
