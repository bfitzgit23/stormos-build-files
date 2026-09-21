message (STATUS "Uninstalling")
message (STATUS "Executing custom uninstall script /usr/bin/python3.14 /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/compizconfig/compizconfig-python/setup.py uninstall --prefix=/usr --version=0.9.14.2")
execute_process (COMMAND /usr/bin/python3.14 /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/compizconfig/compizconfig-python/setup.py uninstall --prefix=/usr --version=0.9.14.2
                 WORKING_DIRECTORY "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/compizconfig/compizconfig-python"
                 OUTPUT_VARIABLE cmd_output
                 RESULT_VARIABLE cmd_ret)
message ("${cmd_output}")
if (NOT "${cmd_ret}" STREQUAL 0)
    message (FATAL_ERROR "Problem executing uninstall script /usr/bin/python3.14 /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/compizconfig/compizconfig-python/setup.py uninstall --prefix=/usr --version=0.9.14.2 : ${cmd_ret}")
endif (NOT "${cmd_ret}" STREQUAL 0)
message (STATUS "Executing custom uninstall script /usr/bin/python3.14 /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/compizconfig/ccsm/setup.py uninstall --prefix=/usr --version=0.9.14.2")
execute_process (COMMAND /usr/bin/python3.14 /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/compizconfig/ccsm/setup.py uninstall --prefix=/usr --version=0.9.14.2
                 WORKING_DIRECTORY "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/compizconfig/ccsm"
                 OUTPUT_VARIABLE cmd_output
                 RESULT_VARIABLE cmd_ret)
message ("${cmd_output}")
if (NOT "${cmd_ret}" STREQUAL 0)
    message (FATAL_ERROR "Problem executing uninstall script /usr/bin/python3.14 /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/compizconfig/ccsm/setup.py uninstall --prefix=/usr --version=0.9.14.2 : ${cmd_ret}")
endif (NOT "${cmd_ret}" STREQUAL 0)
message (STATUS "Executing custom uninstall script cmake -DSCHEMADIR_USER=/usr/share/glib-2.0/schemas -DSCHEMADIR_ROOT=/usr/share/glib-2.0/schemas -P /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/recompile_gsettings_schemas_in_dir_user_env.cmake")
execute_process (COMMAND cmake -DSCHEMADIR_USER=/usr/share/glib-2.0/schemas -DSCHEMADIR_ROOT=/usr/share/glib-2.0/schemas -P /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/recompile_gsettings_schemas_in_dir_user_env.cmake
                 WORKING_DIRECTORY "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/postinst"
                 OUTPUT_VARIABLE cmd_output
                 RESULT_VARIABLE cmd_ret)
message ("${cmd_output}")
if (NOT "${cmd_ret}" STREQUAL 0)
    message (FATAL_ERROR "Problem executing uninstall script cmake -DSCHEMADIR_USER=/usr/share/glib-2.0/schemas -DSCHEMADIR_ROOT=/usr/share/glib-2.0/schemas -P /home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/compiz-0.9.14.2/cmake/recompile_gsettings_schemas_in_dir_user_env.cmake : ${cmd_ret}")
endif (NOT "${cmd_ret}" STREQUAL 0)
if (NOT EXISTS "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/install_manifest.txt")
  message (FATAL_ERROR "Cannot find install manifest: \"/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/install_manifest.txt\"")
endif (NOT EXISTS "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/install_manifest.txt")

file (READ "/home/bennji/Desktop/stormos-build-files/compiz-easy-patch/src/build/install_manifest.txt" files)
string (REGEX REPLACE "\n" ";" files "${files}")
foreach (file ${files})
  message (STATUS "Uninstalling \"${file}\"")
  if (EXISTS "${file}")
    exec_program(
      "/usr/bin/cmake" ARGS "-E remove \"${file}\""
      OUTPUT_VARIABLE rm_out
      RETURN_VALUE rm_retval
      )
    if ("${rm_retval}" STREQUAL 0)
    else ("${rm_retval}" STREQUAL 0)
      message (FATAL_ERROR "Problem when removing \"${file}\"")
    endif ("${rm_retval}" STREQUAL 0)
  else (EXISTS "${file}")
    message (STATUS "File \"${file}\" does not exist.")
  endif (EXISTS "${file}")
endforeach (file)
