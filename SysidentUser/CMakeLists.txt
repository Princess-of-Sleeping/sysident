cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(SysidentUser)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

enable_language(C ASM)

include_directories(
)

link_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(SysidentUser
  src/main.c
  src/taihen_min.c
  src/i2f.S
)

target_link_libraries(SysidentUser
  SceLibKernel_stub
  SceSblSsMgr_stub
  SceSblPostSsMgr_stub
  SceKernelModulemgr_stub
  SceKernelThreadMgr_stub
  SceSysmem_stub
  SceVshBridge_stub
  taihen_stub
  ${CMAKE_CURRENT_BINARY_DIR}/../SysidentKernel/libSysidentKernel_stub_weak.a
)

set_target_properties(SysidentUser
  PROPERTIES LINK_FLAGS "-nostdlib"
)

vita_create_self(sysident.suprx SysidentUser
  CONFIG exports.yml
  UNSAFE
)

