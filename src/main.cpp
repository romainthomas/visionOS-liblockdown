#include "log.hpp"
#include <QBDL/QBDL.hpp>
#include <LIEF/LIEF.hpp>

#include <llvm/Support/Signals.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/ADT/StringRef.h>

#include <QBDI.h>
#include <dlfcn.h>

struct FinalTargetSystem: public QBDL::Engines::Native::TargetSystem {
  using QBDL::Engines::Native::TargetSystem::TargetSystem;

  uint64_t symlink(QBDL::Loader &generic, const LIEF::Symbol &gen_sym) override {
    auto& loader = static_cast<QBDL::Loaders::MachO&>(generic);
    const auto& symbol = static_cast<const LIEF::MachO::Symbol&>(gen_sym);

    LK_INFO("Resolving {}", symbol.name());

    const LIEF::MachO::DylibCommand* lib = symbol.library();
    if (lib == nullptr) {
      LK_ERR("Missing library for {}", symbol.name());
      return 0;
    }

    void* hdl = dlopen(lib->name().c_str(), /*mode=*/RTLD_NOW);
    if (hdl == nullptr) {
      LK_ERR("Can't dlopen({})", lib->name());
      return 0;
    }

    std::string normalized = symbol.name();
    if (!normalized.empty() && normalized[0] == '_') {
      normalized = normalized.substr(1);
    }

    void* addr = dlsym(hdl, normalized.c_str());
    if (addr == nullptr) {
      LK_ERR("Can't find '{}' in {}", symbol.name(), lib->name());
      return 0;
    }
    return (uint64_t)addr;
  }
};

int main(int argc, const char** argv) {
  LIEF::logging::set_level(LIEF::logging::LEVEL::INFO);
  QBDL::setLogLevel(QBDL::LogLevel::warn);
  QBDI::setLogPriority(QBDI::LogPriority::WARNING);
  if (argc != 2) {
    LK_ERR("Usage: {} <path>/liblockdown.dylib", argv[0]);
    return EXIT_FAILURE;
  }
  const char* path = argv[1];

  LK_INFO("Loading {}", path);

  llvm::sys::PrintStackTraceOnErrorSignal("liblockdown.dylib - lifter");

  auto mem = std::make_unique<QBDL::Engines::Native::TargetMemory>();
  auto system = std::make_unique<FinalTargetSystem>(*mem);

  auto loader = QBDL::Loaders::MachO::from_file(
    path, QBDL::Engines::Native::arch(), *system, QBDL::Loader::BIND::NOW);

  if (loader == nullptr) {
    LK_ERR("QBDL loading failed!");
    return EXIT_FAILURE;
  }
  uint64_t lockdown_connect_addr = loader->get_address("_lockdown_connect");
  LK_INFO("_lockdown_connect: 0x{:016x}", lockdown_connect_addr);

  QBDI::VM vm;

  static constexpr size_t STACK_SIZE = 0x30000;
  void* stack_ptr = alloca(STACK_SIZE);

  auto bp = (uintptr_t)stack_ptr;
  uintptr_t sp = bp + STACK_SIZE;

  const uintptr_t pc = lockdown_connect_addr;
  const uintptr_t lr = loader->base_address() + 0x24F869184 - loader->get_binary().imagebase();

  QBDI::GPRState* state = vm.getGPRState();
  state->x29 = bp;
  state->sp  = sp;
  state->pc = pc;
  state->lr = lr;
  vm.setGPRState(state);

  uint64_t start = loader->base_address();
  uint64_t end = start + loader->get_binary().virtual_size();
  vm.addInstrumentedRange(start, end);

  vm.addCodeAddrCB(lr, QBDI::POSTINST,
    [] (QBDI::VM*, QBDI::GPRState*, QBDI::FPRState*, void*) {
      return QBDI::STOP;
  }, nullptr);

  vm.addCodeCB(QBDI::InstPosition::PREINST,
    [] (QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState*, void* data) {
      const QBDI::InstAnalysis* inst = vm->getInstAnalysis();
      LK_INFO("0x{:016x}: {}", inst->address, inst->disassembly);
      return QBDI::VMAction::CONTINUE;
  }, nullptr);

  const uint64_t addr = 0x24F869090 - loader->get_binary().imagebase() +
                        loader->base_address();
  vm.addCodeAddrCB(addr, QBDI::PREINST,
                   [] (QBDI::VM*, QBDI::GPRState* gpr, QBDI::FPRState*, void*) {
                    LK_INFO("X20: {}", (const char*)gpr->x20);
                    return QBDI::VMAction::STOP;
                   }, nullptr);

  vm.run(lockdown_connect_addr, lr);

  return 0;
}
