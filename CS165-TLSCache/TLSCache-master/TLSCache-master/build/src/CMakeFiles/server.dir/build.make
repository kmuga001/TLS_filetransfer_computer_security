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
CMAKE_COMMAND = /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/extern/cmake/bin/cmake

# The command to remove a file.
RM = /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/extern/cmake/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build

# Include any dependencies generated for this target.
include src/CMakeFiles/server.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/server.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/server.dir/flags.make

src/CMakeFiles/server.dir/server/server.c.o: src/CMakeFiles/server.dir/flags.make
src/CMakeFiles/server.dir/server/server.c.o: ../src/server/server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/server.dir/server/server.c.o"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/server.dir/server/server.c.o   -c /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/src/server/server.c

src/CMakeFiles/server.dir/server/server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/server.dir/server/server.c.i"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/src/server/server.c > CMakeFiles/server.dir/server/server.c.i

src/CMakeFiles/server.dir/server/server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/server.dir/server/server.c.s"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/src/server/server.c -o CMakeFiles/server.dir/server/server.c.s

# Object files for target server
server_OBJECTS = \
"CMakeFiles/server.dir/server/server.c.o"

# External object files for target server
server_EXTERNAL_OBJECTS =

src/server: src/CMakeFiles/server.dir/server/server.c.o
src/server: src/CMakeFiles/server.dir/build.make
src/server: ../extern/libressl_install/lib/libtls.so
src/server: ../extern/libressl_install/lib/libssl.so
src/server: ../extern/libressl_install/lib/libcrypto.so
src/server: src/CMakeFiles/server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable server"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/server.dir/build: src/server

.PHONY : src/CMakeFiles/server.dir/build

src/CMakeFiles/server.dir/clean:
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/src && $(CMAKE_COMMAND) -P CMakeFiles/server.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/server.dir/clean

src/CMakeFiles/server.dir/depend:
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/src /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/src /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/src/CMakeFiles/server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/server.dir/depend

