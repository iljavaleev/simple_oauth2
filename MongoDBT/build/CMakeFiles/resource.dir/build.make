# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.30

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
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.30.2/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.30.2/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/ilavaleev/Dev/OAUTH2/MongoDBT

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/ilavaleev/Dev/OAUTH2/MongoDBT/build

# Include any dependencies generated for this target.
include CMakeFiles/resource.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/resource.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/resource.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/resource.dir/flags.make

CMakeFiles/resource.dir/main.cpp.o: CMakeFiles/resource.dir/flags.make
CMakeFiles/resource.dir/main.cpp.o: /Users/ilavaleev/Dev/OAUTH2/MongoDBT/main.cpp
CMakeFiles/resource.dir/main.cpp.o: CMakeFiles/resource.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/ilavaleev/Dev/OAUTH2/MongoDBT/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/resource.dir/main.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/resource.dir/main.cpp.o -MF CMakeFiles/resource.dir/main.cpp.o.d -o CMakeFiles/resource.dir/main.cpp.o -c /Users/ilavaleev/Dev/OAUTH2/MongoDBT/main.cpp

CMakeFiles/resource.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/resource.dir/main.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/ilavaleev/Dev/OAUTH2/MongoDBT/main.cpp > CMakeFiles/resource.dir/main.cpp.i

CMakeFiles/resource.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/resource.dir/main.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/ilavaleev/Dev/OAUTH2/MongoDBT/main.cpp -o CMakeFiles/resource.dir/main.cpp.s

# Object files for target resource
resource_OBJECTS = \
"CMakeFiles/resource.dir/main.cpp.o"

# External object files for target resource
resource_EXTERNAL_OBJECTS =

resource: CMakeFiles/resource.dir/main.cpp.o
resource: CMakeFiles/resource.dir/build.make
resource: /opt/homebrew/lib/libpqxx.dylib
resource: /opt/homebrew/lib/libmongocxx.3.10.2.dylib
resource: /opt/homebrew/lib/libbsoncxx.3.10.2.dylib
resource: /opt/homebrew/Cellar/openssl@3/3.3.1/lib/libssl.dylib
resource: /opt/homebrew/Cellar/openssl@3/3.3.1/lib/libcrypto.dylib
resource: CMakeFiles/resource.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/ilavaleev/Dev/OAUTH2/MongoDBT/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable resource"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/resource.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/resource.dir/build: resource
.PHONY : CMakeFiles/resource.dir/build

CMakeFiles/resource.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/resource.dir/cmake_clean.cmake
.PHONY : CMakeFiles/resource.dir/clean

CMakeFiles/resource.dir/depend:
	cd /Users/ilavaleev/Dev/OAUTH2/MongoDBT/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/ilavaleev/Dev/OAUTH2/MongoDBT /Users/ilavaleev/Dev/OAUTH2/MongoDBT /Users/ilavaleev/Dev/OAUTH2/MongoDBT/build /Users/ilavaleev/Dev/OAUTH2/MongoDBT/build /Users/ilavaleev/Dev/OAUTH2/MongoDBT/build/CMakeFiles/resource.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/resource.dir/depend

