cmake_minimum_required(VERSION 3.24)
enable_language(CXX)

project(LockLifter VERSION 1.0.0)

find_package(LIEF REQUIRED)
find_package(QBDI REQUIRED)
find_package(QBDL REQUIRED)
find_package(spdlog REQUIRED)
find_package(LLVM REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(lock-lifter src/main.cpp)

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

target_link_libraries(lock-lifter PRIVATE
  LIEF::LIEF
  spdlog::spdlog
  QBDL::QBDL
  ${QBDI_STATIC_LIBRARY}
)

target_include_directories(lock-lifter PUBLIC
  ${QBDI_INCLUDE_DIR}
)

target_link_libraries(lock-lifter
  PUBLIC
    LLVMSupport
    LLVMCore
    LLVMCodeGen
    LLVMAsmPrinter
    LLVMBinaryFormat
    LLVMAnalysis
    LLVMMCDisassembler
    LLVMMCJIT
    LLVMTarget
    LLVMAsmParser
  PUBLIC
    LLVMAArch64CodeGen
    LLVMAArch64AsmParser
    LLVMAArch64Disassembler
    LLVMAArch64Desc
    LLVMAArch64Info
    LLVMAArch64Utils
  PUBLIC
    LLVMX86CodeGen
    LLVMX86AsmParser
    LLVMX86Disassembler
    LLVMX86Desc
    LLVMX86Info
  PUBLIC
    LLVMARMCodeGen
    LLVMARMAsmParser
    LLVMARMDisassembler
    LLVMARMDesc
    LLVMARMInfo
    LLVMARMUtils
)
