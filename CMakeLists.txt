cmake_minimum_required(VERSION 3.16)
project(robohub-transport C)

# ---------------------------------------------------------------------------
# Locating sibling modules
# ---------------------------------------------------------------------------
# Framing sits between the physical link and the runtime, so it needs the common
# contracts and the core event bus it publishes onto. Paths are never hard-coded:
# a variable the parent build already set (rho writes one for every dependency)
# wins, then the environment, then a sibling checkout, then a fetch.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps.cmake")
  include("${CMAKE_CURRENT_SOURCE_DIR}/deps.cmake")
endif()

function(robohub_locate_module module out_var)
  string(TOUPPER "${module}" upper)
  string(REPLACE "-" "_" upper "${upper}")
  if(${out_var})
    return()
  endif()
  if(DEFINED ENV{${upper}_DIR})
    set(${out_var} "$ENV{${upper}_DIR}" PARENT_SCOPE)
    return()
  endif()
  set(dir "${CMAKE_CURRENT_SOURCE_DIR}")
  foreach(level RANGE 6)
    get_filename_component(parent "${dir}/.." ABSOLUTE)
    if(EXISTS "${parent}/${module}/CMakeLists.txt")
      set(${out_var} "${parent}/${module}" PARENT_SCOPE)
      return()
    endif()
    set(dir "${parent}")
  endforeach()
  include(FetchContent)
  message(STATUS "[${PROJECT_NAME}] fetching ${module}")
  FetchContent_Declare(${module}
    GIT_REPOSITORY "https://github.com/RoboHubPlatform/${module}.git"
    GIT_TAG main GIT_SHALLOW TRUE GIT_PROGRESS TRUE)
  FetchContent_MakeAvailable(${module})
  set(${out_var} "${${module}_SOURCE_DIR}" PARENT_SCOPE)
endfunction()

robohub_locate_module(robohub-common ROBOHUB_COMMON_DIR)
robohub_locate_module(robohub-core ROBOHUB_CORE_DIR)
if(NOT ROBOHUB_COMMON_DIR OR NOT ROBOHUB_CORE_DIR)
  message(FATAL_ERROR "robohub-common or robohub-core not found and could not be fetched")
endif()
message(STATUS "[${PROJECT_NAME}] robohub-common at ${ROBOHUB_COMMON_DIR}")
message(STATUS "[${PROJECT_NAME}] robohub-core at ${ROBOHUB_CORE_DIR}")

if(PROJECT_IS_TOP_LEVEL)
  add_subdirectory("${ROBOHUB_COMMON_DIR}" robohub-common)
  add_subdirectory("${ROBOHUB_CORE_DIR}" robohub-core)
endif()

# ---------------------------------------------------------------------------
# Library target
# ---------------------------------------------------------------------------
add_library(robohub-transport STATIC src/transport.c)

target_include_directories(robohub-transport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${ROBOHUB_COMMON_DIR}/include
    ${ROBOHUB_COMMON_DIR}/include/robohub
    ${ROBOHUB_CORE_DIR}/include
)
target_link_libraries(robohub-transport PUBLIC robohub-common robohub-core)
target_compile_features(robohub-transport PUBLIC c_std_11)

# ---------------------------------------------------------------------------
# Host tests
# ---------------------------------------------------------------------------
# Framing is ordinary portable C and runs on the machine doing the building. The
# test drives the event bus directly, so it reaches the core's private initialiser
# the way a runtime would.
if(PROJECT_IS_TOP_LEVEL AND RHO_BUILD_HOST_TESTS AND NOT RHO_TARGET_IS_BAREMETAL)
  message(STATUS "[${PROJECT_NAME}] registering host unit tests")
  enable_testing()
  add_executable(robohub-transport-test tests/test_transport.c)
  target_link_libraries(robohub-transport-test PRIVATE robohub-transport)
  target_include_directories(robohub-transport-test PRIVATE "${ROBOHUB_CORE_DIR}/src")
  add_test(NAME robohub-transport-test COMMAND robohub-transport-test)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(FILES module.yml DESTINATION share/robohub-transport)
install(DIRECTORY include/ DESTINATION include)
install(TARGETS robohub-transport
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)
