add_llvm_library(SeaTransformsUtils DISABLE_LLVM_LINK_LLVM_DYLIB
  AbstractMemory.cc
  DummyExitBlock.cc
  Local.cc
  MarkInternalInline.cc
  MarkInternalSpecialFunctions.cc
  NameValues.cc
  RemoveUnreachableBlocksPass.cc
  DummyMainFunction.cc
  EvalBranchSentinelPass.cc
  ExternalizeAddressTakenFunctions.cc
  ExternalizeFunctions.cc
  DevirtFunctions.cc
  DevirtFunctionsPass.cc
  SliceFunctions.cc
  Mem2Reg.cc
  OneAssumePerBlock.cc
  SliceFunctions.cc
  DebugVerifier.cc
  )
