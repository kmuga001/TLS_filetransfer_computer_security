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
include solution/CMakeFiles/server_solution.dir/depend.make

# Include the progress variables for this target.
include solution/CMakeFiles/server_solution.dir/progress.make

# Include the compile flags for this target's objects.
include solution/CMakeFiles/server_solution.dir/flags.make

solution/CMakeFiles/server_solution.dir/server_solution/server.c.o: solution/CMakeFiles/server_solution.dir/flags.make
solution/CMakeFiles/server_solution.dir/server_solution/server.c.o: ../solution/server_solution/server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object solution/CMakeFiles/server_solution.dir/server_solution/server.c.o"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/solution && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/server_solution.dir/server_solution/server.c.o   -c /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/solution/server_solution/server.c

solution/CMakeFiles/server_solution.dir/server_solution/server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/server_solution.dir/server_solution/server.c.i"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/solution && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/solution/server_solution/server.c > CMakeFiles/server_solution.dir/server_solution/server.c.i

solution/CMakeFiles/server_solution.dir/server_solution/server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/server_solution.dir/server_solution/server.c.s"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/solution && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/solution/server_solution/server.c -o CMakeFiles/server_solution.dir/server_solution/server.c.s

# Object files for target server_solution
server_solution_OBJECTS = \
"CMakeFiles/server_solution.dir/server_solution/server.c.o"

# External object files for target server_solution
server_solution_EXTERNAL_OBJECTS =

solution/server_solution: solution/CMakeFiles/server_solution.dir/server_solution/server.c.o
solution/server_solution: solution/CMakeFiles/server_solution.dir/build.make
solution/server_solution: ../extern/libressl_install/lib/libtls.so
solution/server_solution: ../extern/libressl_install/lib/libssl.so
solution/server_solution: ../extern/libressl_install/lib/libcrypto.so
solution/server_solution: solution/CMakeFiles/server_solution.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable server_solution"
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/solution && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server_solution.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
solution/CMakeFiles/server_solution.dir/build: solution/server_solution

.PHONY : solution/CMakeFiles/server_solution.dir/build

solution/CMakeFiles/server_solution.dir/clean:
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/solution && $(CMAKE_COMMAND) -P CMakeFiles/server_solution.dir/cmake_clean.cmake
.PHONY : solution/CMakeFiles/server_solution.dir/clean

solution/CMakeFiles/server_solution.dir/depend:
	cd /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/solution /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/solution /home/csmajs/kmuga001/CS_165PROJECT/CS165-TLSCache/TLSCache-master/TLSCache-master/build/solution/CMakeFiles/server_solution.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : solution/CMakeFiles/server_solution.dir/depend

