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
include tests/CMakeFiles/explicit_bzero.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/explicit_bzero.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/explicit_bzero.dir/flags.make

tests/CMakeFiles/explicit_bzero.dir/explicit_bzero.c.o: tests/CMakeFiles/explicit_bzero.dir/flags.make
tests/CMakeFiles/explicit_bzero.dir/explicit_bzero.c.o: ../tests/explicit_bzero.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/explicit_bzero.dir/explicit_bzero.c.o"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/explicit_bzero.dir/explicit_bzero.c.o   -c /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/explicit_bzero.c

tests/CMakeFiles/explicit_bzero.dir/explicit_bzero.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/explicit_bzero.dir/explicit_bzero.c.i"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/explicit_bzero.c > CMakeFiles/explicit_bzero.dir/explicit_bzero.c.i

tests/CMakeFiles/explicit_bzero.dir/explicit_bzero.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/explicit_bzero.dir/explicit_bzero.c.s"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/explicit_bzero.c -o CMakeFiles/explicit_bzero.dir/explicit_bzero.c.s

# Object files for target explicit_bzero
explicit_bzero_OBJECTS = \
"CMakeFiles/explicit_bzero.dir/explicit_bzero.c.o"

# External object files for target explicit_bzero
explicit_bzero_EXTERNAL_OBJECTS =

tests/explicit_bzero: tests/CMakeFiles/explicit_bzero.dir/explicit_bzero.c.o
tests/explicit_bzero: tests/CMakeFiles/explicit_bzero.dir/build.make
tests/explicit_bzero: tls/libtls.so.20.1.0
tests/explicit_bzero: ssl/libssl.so.48.1.0
tests/explicit_bzero: crypto/libcrypto.so.46.1.0
tests/explicit_bzero: tests/CMakeFiles/explicit_bzero.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable explicit_bzero"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/explicit_bzero.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/explicit_bzero.dir/build: tests/explicit_bzero

.PHONY : tests/CMakeFiles/explicit_bzero.dir/build

tests/CMakeFiles/explicit_bzero.dir/clean:
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/explicit_bzero.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/explicit_bzero.dir/clean

tests/CMakeFiles/explicit_bzero.dir/depend:
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests/CMakeFiles/explicit_bzero.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/explicit_bzero.dir/depend

