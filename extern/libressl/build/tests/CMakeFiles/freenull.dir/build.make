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
include tests/CMakeFiles/freenull.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/freenull.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/freenull.dir/flags.make

tests/CMakeFiles/freenull.dir/freenull.c.o: tests/CMakeFiles/freenull.dir/flags.make
tests/CMakeFiles/freenull.dir/freenull.c.o: ../tests/freenull.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/freenull.dir/freenull.c.o"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/freenull.dir/freenull.c.o   -c /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/freenull.c

tests/CMakeFiles/freenull.dir/freenull.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/freenull.dir/freenull.c.i"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/freenull.c > CMakeFiles/freenull.dir/freenull.c.i

tests/CMakeFiles/freenull.dir/freenull.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/freenull.dir/freenull.c.s"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests/freenull.c -o CMakeFiles/freenull.dir/freenull.c.s

# Object files for target freenull
freenull_OBJECTS = \
"CMakeFiles/freenull.dir/freenull.c.o"

# External object files for target freenull
freenull_EXTERNAL_OBJECTS =

tests/freenull: tests/CMakeFiles/freenull.dir/freenull.c.o
tests/freenull: tests/CMakeFiles/freenull.dir/build.make
tests/freenull: tls/libtls.so.20.1.0
tests/freenull: ssl/libssl.so.48.1.0
tests/freenull: crypto/libcrypto.so.46.1.0
tests/freenull: tests/CMakeFiles/freenull.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable freenull"
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/freenull.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/freenull.dir/build: tests/freenull

.PHONY : tests/CMakeFiles/freenull.dir/build

tests/CMakeFiles/freenull.dir/clean:
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/freenull.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/freenull.dir/clean

tests/CMakeFiles/freenull.dir/depend:
	cd /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/tests /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests /home/csmajs/kmuga001/CS_165PROJECT/extern/libressl/build/tests/CMakeFiles/freenull.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/freenull.dir/depend

