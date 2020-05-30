cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(SysidentKernel)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

enable_language(C ASM)

add_executable(SysidentKernel
  src/main.c
)

target_link_libraries(SysidentKernel
  SceDebugForDriver_stub
  SceIofilemgrForDriver_stub
  SceSblSsMgrForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceThreadmgrForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub
)

set_target_properties(SysidentKernel
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__VITA_KERNEL__"
)

vita_create_self(sysident.skprx SysidentKernel
  CONFIG exports.yml
  UNSAFE
)

vita_create_stubs(stubs SysidentKernel ${CMAKE_SOURCE_DIR}/exports.yml KERNEL)