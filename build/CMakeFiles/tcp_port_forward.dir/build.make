# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

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

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kzj/epoll-tcp-port-forward

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kzj/epoll-tcp-port-forward/build

# Include any dependencies generated for this target.
include CMakeFiles/tcp_port_forward.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/tcp_port_forward.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/tcp_port_forward.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/tcp_port_forward.dir/flags.make

CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o: CMakeFiles/tcp_port_forward.dir/flags.make
CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o: /home/kzj/epoll-tcp-port-forward/tcp_port_forward.c
CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o: CMakeFiles/tcp_port_forward.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kzj/epoll-tcp-port-forward/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o -MF CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o.d -o CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o -c /home/kzj/epoll-tcp-port-forward/tcp_port_forward.c

CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/kzj/epoll-tcp-port-forward/tcp_port_forward.c > CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.i

CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/kzj/epoll-tcp-port-forward/tcp_port_forward.c -o CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.s

# Object files for target tcp_port_forward
tcp_port_forward_OBJECTS = \
"CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o"

# External object files for target tcp_port_forward
tcp_port_forward_EXTERNAL_OBJECTS =

tcp_port_forward: CMakeFiles/tcp_port_forward.dir/tcp_port_forward.c.o
tcp_port_forward: CMakeFiles/tcp_port_forward.dir/build.make
tcp_port_forward: CMakeFiles/tcp_port_forward.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kzj/epoll-tcp-port-forward/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable tcp_port_forward"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tcp_port_forward.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/tcp_port_forward.dir/build: tcp_port_forward
.PHONY : CMakeFiles/tcp_port_forward.dir/build

CMakeFiles/tcp_port_forward.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/tcp_port_forward.dir/cmake_clean.cmake
.PHONY : CMakeFiles/tcp_port_forward.dir/clean

CMakeFiles/tcp_port_forward.dir/depend:
	cd /home/kzj/epoll-tcp-port-forward/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kzj/epoll-tcp-port-forward /home/kzj/epoll-tcp-port-forward /home/kzj/epoll-tcp-port-forward/build /home/kzj/epoll-tcp-port-forward/build /home/kzj/epoll-tcp-port-forward/build/CMakeFiles/tcp_port_forward.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/tcp_port_forward.dir/depend

