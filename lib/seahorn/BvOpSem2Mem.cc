/**
   Memory related functions from Bv2OpSem.
   Adapted from llvm::ExecutionEngine
 */

#include "BvOpSem2Context.hh"
#include "seahorn/Support/SeaDebug.h"
#include "seahorn/Support/SeaLog.hh"

using namespace llvm;
namespace seahorn {
namespace details {
/// from: llvm/lib/ExecutionEngine/ExecutionEngine.cpp
void ConstantExprEvaluator::storeValueToMemory(const GenericValue &Val,
                                               GenericValue *Ptr, Type *Ty) {
  const unsigned StoreBytes = getDataLayout().getTypeStoreSize(Ty);

  switch (Ty->getTypeID()) {
  default:
    dbgs() << "Cannot store value of type " << *Ty << "!\n";
    break;
  case Type::IntegerTyID:
    StoreIntToMemory(Val.IntVal, (uint8_t *)Ptr, StoreBytes);
    break;
  case Type::FloatTyID:
    *((float *)Ptr) = Val.FloatVal;
    break;
  case Type::DoubleTyID:
    *((double *)Ptr) = Val.DoubleVal;
    break;
  case Type::X86_FP80TyID:
    memcpy(Ptr, Val.IntVal.getRawData(), 10);
    break;
  case Type::PointerTyID:
    // Ensure 64 bit target pointers are fully initialized on 32 bit hosts.
    if (StoreBytes != sizeof(PointerTy))
      memset(&(Ptr->PointerVal), 0, StoreBytes);

    *((PointerTy *)Ptr) = Val.PointerVal;
    break;
  case Type::VectorTyID:
    for (unsigned i = 0; i < Val.AggregateVal.size(); ++i) {
      if (cast<VectorType>(Ty)->getElementType()->isDoubleTy())
        *(((double *)Ptr) + i) = Val.AggregateVal[i].DoubleVal;
      if (cast<VectorType>(Ty)->getElementType()->isFloatTy())
        *(((float *)Ptr) + i) = Val.AggregateVal[i].FloatVal;
      if (cast<VectorType>(Ty)->getElementType()->isIntegerTy()) {
        unsigned numOfBytes =
            (Val.AggregateVal[i].IntVal.getBitWidth() + 7) / 8;
        StoreIntToMemory(Val.AggregateVal[i].IntVal,
                         (uint8_t *)Ptr + numOfBytes * i, numOfBytes);
      }
    }
    break;
  }

  if (sys::IsLittleEndianHost != getDataLayout().isLittleEndian())
    // Host and target are different endian - reverse the stored bytes.
    std::reverse((uint8_t *)Ptr, StoreBytes + (uint8_t *)Ptr);
}

/// from: llvm/lib/ExecutionEngine/ExecutionEngine.cpp
void ConstantExprEvaluator::initMemory(const Constant *Init, void *Addr) {
  // LOG("opsem", errs() << "Initializing constant:\n"; Init->dump(););

  if (isa<UndefValue>(Init))
    return;

  if (const ConstantVector *CP = dyn_cast<ConstantVector>(Init)) {
    unsigned ElementSize =
        getDataLayout().getTypeAllocSize(CP->getType()->getElementType());
    for (unsigned i = 0, e = CP->getNumOperands(); i != e; ++i)
      initMemory(CP->getOperand(i), (char *)Addr + i * ElementSize);
    return;
  }

  if (isa<ConstantAggregateZero>(Init)) {
    memset(Addr, 0, (size_t)getDataLayout().getTypeAllocSize(Init->getType()));
    return;
  }

  if (const ConstantArray *CPA = dyn_cast<ConstantArray>(Init)) {
    unsigned ElementSize =
        getDataLayout().getTypeAllocSize(CPA->getType()->getElementType());
    for (unsigned i = 0, e = CPA->getNumOperands(); i != e; ++i)
      initMemory(CPA->getOperand(i), (char *)Addr + i * ElementSize);
    return;
  }

  if (const ConstantStruct *CPS = dyn_cast<ConstantStruct>(Init)) {
    const StructLayout *SL =
        getDataLayout().getStructLayout(cast<StructType>(CPS->getType()));
    for (unsigned i = 0, e = CPS->getNumOperands(); i != e; ++i)
      initMemory(CPS->getOperand(i), (char *)Addr + SL->getElementOffset(i));
    return;
  }

  if (const ConstantDataSequential *CDS =
          dyn_cast<ConstantDataSequential>(Init)) {
    // CDS is already laid out in host memory order.
    StringRef Data = CDS->getRawDataValues();
    memcpy(Addr, Data.data(), Data.size());
    return;
  }

  if (Init->getType()->isFirstClassType()) {
    auto valo = evaluate(Init);
    if (valo)
      storeValueToMemory(valo.getValue(), (GenericValue *)Addr,
                         Init->getType());
    return;
  }

  ERR << "Bad Type: " << *Init->getType();
  llvm_unreachable("Unknown constant type to initialize memory with!");
}

} // namespace details
} // namespace seahorn
