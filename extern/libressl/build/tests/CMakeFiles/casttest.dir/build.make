# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/csmajs/kmuga001/CS_165PROJECT/extern/cmake/bin/cmake

# The command to remove a file.
RM = /home/csmajs/kmuga001/CS_165PROJECT/extern/cmake/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/casttest.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/casttest.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/casttest.dir/flags.make

tests/CMakeFiles/casttest.dir/casttest.c.o: tests/CMakeFiles/casttest.dir/flags.make
tests/CMakeFiles/casttest.dir/casttest.c.o: ../tests/casttest.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/casttest.dir/casttest.c.o"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/casttest.dir/casttest.c.o   -c /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/casttest.c

tests/CMakeFiles/casttest.dir/casttest.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/casttest.dir/casttest.c.i"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/casttest.c > CMakeFiles/casttest.dir/casttest.c.i

tests/CMakeFiles/casttest.dir/casttest.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/casttest.dir/casttest.c.s"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/casttest.c -o CMakeFiles/casttest.dir/casttest.c.s

# Object files for target casttest
casttest_OBJECTS = \
"CMakeFiles/casttest.dir/casttest.c.o"

# External object files for target casttest
casttest_EXTERNAL_OBJECTS =

tests/casttest: tests/CMakeFiles/casttest.dir/casttest.c.o
tests/casttest: tests/CMakeFiles/casttest.dir/build.make
tests/casttest: tls/libtls.so.20.1.0
tests/casttest: ssl/libssl.so.48.1.0
tests/casttest: crypto/libcrypto.so.46.1.0
tests/casttest: tests/CMakeFiles/casttest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable casttest"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/casttest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/casttest.dir/build: tests/casttest

.PHONY : tests/CMakeFiles/casttest.dir/build

tests/CMakeFiles/casttest.dir/clean:
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/casttest.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/casttest.dir/clean

tests/CMakeFiles/casttest.dir/depend:
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests/CMakeFiles/casttest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/casttest.dir/depend

