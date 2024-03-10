# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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
CMAKE_SOURCE_DIR = /home/wbli/z-stack

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/wbli/z-stack

# Include any dependencies generated for this target.
include CMakeFiles/tcp_server.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/tcp_server.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/tcp_server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/tcp_server.dir/flags.make

CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o: CMakeFiles/tcp_server.dir/flags.make
CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o: examples/tcp_server/main.c
CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o: CMakeFiles/tcp_server.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wbli/z-stack/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o -MF CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o.d -o CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o -c /home/wbli/z-stack/examples/tcp_server/main.c

CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/wbli/z-stack/examples/tcp_server/main.c > CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.i

CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/wbli/z-stack/examples/tcp_server/main.c -o CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.s

CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o: CMakeFiles/tcp_server.dir/flags.make
CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o: examples/tcp_server/server.c
CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o: CMakeFiles/tcp_server.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wbli/z-stack/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o -MF CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o.d -o CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o -c /home/wbli/z-stack/examples/tcp_server/server.c

CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/wbli/z-stack/examples/tcp_server/server.c > CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.i

CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/wbli/z-stack/examples/tcp_server/server.c -o CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.s

# Object files for target tcp_server
tcp_server_OBJECTS = \
"CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o" \
"CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o"

# External object files for target tcp_server
tcp_server_EXTERNAL_OBJECTS =

tcp_server: CMakeFiles/tcp_server.dir/examples/tcp_server/main.c.o
tcp_server: CMakeFiles/tcp_server.dir/examples/tcp_server/server.c.o
tcp_server: CMakeFiles/tcp_server.dir/build.make
tcp_server: libz-stack.a
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_bpf.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_flow_classify.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_pipeline.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_table.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_port.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_fib.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_ipsec.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_vhost.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_stack.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_security.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_sched.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_reorder.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_rib.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_rcu.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_rawdev.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_pdump.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_power.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_member.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_lpm.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_latencystats.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_kni.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_jobstats.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_ip_frag.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_gso.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_gro.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_eventdev.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_efd.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_distributor.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_cryptodev.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_compressdev.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_cfgfile.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_bitratestats.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_bbdev.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_acl.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_timer.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_hash.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_metrics.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_cmdline.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_pci.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_ethdev.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_meter.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_net.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_mbuf.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_mempool.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_ring.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_eal.so
tcp_server: /usr/local/lib/x86_64-linux-gnu/librte_kvargs.so
tcp_server: /usr/lib/x86_64-linux-gnu/libbsd.so
tcp_server: CMakeFiles/tcp_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wbli/z-stack/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable tcp_server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tcp_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/tcp_server.dir/build: tcp_server
.PHONY : CMakeFiles/tcp_server.dir/build

CMakeFiles/tcp_server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/tcp_server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/tcp_server.dir/clean

CMakeFiles/tcp_server.dir/depend:
	cd /home/wbli/z-stack && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wbli/z-stack /home/wbli/z-stack /home/wbli/z-stack /home/wbli/z-stack /home/wbli/z-stack/CMakeFiles/tcp_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/tcp_server.dir/depend

