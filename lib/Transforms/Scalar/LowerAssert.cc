#include "seahorn/Support/SeaDebug.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
using namespace llvm;

/* Replace assertions to calls to assume */

namespace seahorn {

class LowerAssert : public ModulePass {
  static char ID;

  Function *assumeFn;
  unsigned num_lowered_asserts;

  void LowerFailCall(CallInst *CI, CallGraph *cg, Function *assumeFn,
                     LLVMContext &ctx);

public:
  LowerAssert() : ModulePass(ID), num_lowered_asserts(0) {}

  bool runOnModule(Module &M) override;

  bool runOnFunction(Function &F);

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<SeaBuiltinsInfoWrapperPass>();
    AU.setPreservesAll(); }

  StringRef getPassName() const override { return "LowerAssert"; }
};

// C assert function is just a macro that calls an assertion handler
// in case of failure. Here we try to detect those assertion
// handlers.
bool isAssertionHandler(Function *F) {
  // --- first, some known assertion handlers

  // on Linux
  if (F->getName().equals("__assert_fail"))
    return true;

  // on Mac OS X
  if (F->getName().equals("__assert_rtn"))
    return true;

  // --- otherwise, we consider the function an assertion handler if
  //     the function does not return.

  if (F->getName().startswith("__assert") && F->doesNotReturn())
    return true;

  return false;
}

bool LowerAssert::runOnModule(Module &M) {

  LLVMContext &Context = M.getContext();

  auto &SBI = getAnalysis<SeaBuiltinsInfoWrapperPass>().getSBI();

  assumeFn = SBI.mkSeaBuiltinFn(SeaBuiltinsOp::ASSUME, M);
  bool Changed = false;
  for (auto &F : M)
    Changed |= runOnFunction(F);

  errs() << "-- Number of asserts converted to assumes=" << num_lowered_asserts
         << "\n";
  return Changed;
}

void getBranchToInsertAssume(
    BasicBlock *BB, std::vector<std::pair<BranchInst *, bool>> &Branches) {
  for (auto it = pred_begin(BB), et = pred_end(BB); it != et; ++it) {
    BasicBlock *Pred = *it;
    auto *TI = Pred->getTerminator();
    if (BranchInst *BI = dyn_cast<BranchInst>(TI)) {
      if (!BI->isConditional())
        return getBranchToInsertAssume(Pred, Branches);
      else
        Branches.push_back(std::make_pair(BI, (BI->getSuccessor(0) == BB)));
    }
  }
}

CmpInst *inverseCmpInst(CmpInst *CI) {
  return CmpInst::Create(CI->getOpcode(), CI->getInversePredicate(),
                         CI->getOperand(0), CI->getOperand(1), "", CI);
}

// CI is a call to verifier.error, __assert_fail, etc.
void LowerAssert::LowerFailCall(CallInst *CI, CallGraph *cg, Function *assumeFn,
                                LLVMContext &ctx) {
  Function *F = CI->getParent()->getParent();

  std::vector<std::pair<BranchInst *, bool>> branches;
  getBranchToInsertAssume(CI->getParent(), branches);

  for (auto p : branches) {
    // p is pair of a branch and a flag such that CI is reachable
    // when the branch condition evaluates to the flag value.
    assert(p.first);

    if (const ConstantInt *CI =
            dyn_cast<const ConstantInt>(p.first->getCondition())) {
      if ((CI->isOne() && p.second) || (CI->isZero() && !p.second)) {
        // error is definitely reachable
        CallInst *NCI =
            CallInst::Create(assumeFn, ConstantInt::getFalse(ctx), "", p.first);
        NCI->setDebugLoc(p.first->getDebugLoc());
        if (cg)
          (*cg)[F]->addCalledFunction(NCI, (*cg)[NCI->getCalledFunction()]);
        num_lowered_asserts++;
      }
      // otherwise the call to verifier.error is dead code.
      continue;
    }

    // verifier.error is reachable if the branch condition is true.
    // Replace with assume(not condition).
    Value *assumeCond = p.first->getCondition();
    if (p.second) {
      if (CmpInst *Cond = dyn_cast<CmpInst>(p.first->getCondition())) {
        // if it's a comparison we flip the operator
        assumeCond = inverseCmpInst(Cond);
      } else {
        // otherwise (e.g., function argument) negate the condition
        // flag.
        IRBuilder<> Builder(ctx);
        Builder.SetInsertPoint(CI);
        assumeCond = Builder.CreateXor(p.first->getCondition(),
                                       ConstantInt::getTrue(ctx));
      }
      assumeCond->setName(p.first->getCondition()->getName());
    }

    // convert the conditional branch into an unconditional one
    if (p.second) // error is reachable if the branch condition is true
      p.first->setCondition(ConstantInt::getFalse(ctx));
    else // error is reachable if the branch condition is false
      p.first->setCondition(ConstantInt::getTrue(ctx));

    CallInst *NCI = CallInst::Create(assumeFn, assumeCond, "", p.first);
    NCI->setDebugLoc(p.first->getDebugLoc());

    LOG("lower-assert", errs()
                            << "Replaced " << *CI << " with " << *NCI << "\n");
    num_lowered_asserts++;

    if (cg)
      (*cg)[F]->addCalledFunction(NCI, (*cg)[NCI->getCalledFunction()]);
  }
}

bool LowerAssert::runOnFunction(Function &F) {
  CallGraphWrapperPass *cgwp = getAnalysisIfAvailable<CallGraphWrapperPass>();
  CallGraph *cg = cgwp ? &cgwp->getCallGraph() : nullptr;
  IRBuilder<> B(F.getContext());

  auto &SBI = getAnalysis<SeaBuiltinsInfoWrapperPass>().getSBI();
  std::vector<CallInst *> Worklist;
  for (auto &BB : F) {
    for (auto &I : BB) {
      CallInst *CI = dyn_cast<CallInst>(&I);
      if (!CI)
        continue;
      Function *CF = CI->getCalledFunction();
      if (!CF)
        continue;

      switch (SBI.getSeaBuiltinOp(*CI)) {
      default:
        if (isAssertionHandler(CF))
          // assertion handler: __assert_fail, __assert_rtn, etc
          Worklist.push_back(CI);
        break;
      case SeaBuiltinsOp::ASSERT:
      case SeaBuiltinsOp::ERROR:
        Worklist.push_back(CI);
        break;
      }
    }
  }
  if (Worklist.empty())
    return true;

  while (!Worklist.empty()) {
    CallInst *CI = Worklist.back();
    Worklist.pop_back();

    Function *CF = CI->getCalledFunction();

    if (SBI.getSeaBuiltinOp(*CI) == SeaBuiltinsOp::ASSERT) {
      CallSite CS(CI);
      Value *Cond = CS.getArgument(0);
      CallInst *NCI = CallInst::Create(
          assumeFn, B.CreateZExtOrTrunc(Cond, Type::getInt1Ty(F.getContext())));
      NCI->setDebugLoc(CI->getDebugLoc());

      LOG("lower-assert",
          errs() << "Replaced " << *CI << " with " << *NCI << "\n");

      num_lowered_asserts++;
      ReplaceInstWithInst(CI, NCI);

      if (cg)
        (*cg)[&F]->addCalledFunction(NCI, (*cg)[NCI->getCalledFunction()]);
    } else if (isAssertionHandler(CF) ||
               SBI.getSeaBuiltinOp(*CI) == SeaBuiltinsOp::ERROR) {
      LowerFailCall(CI, cg, assumeFn, F.getContext());
    }
  }

  return true;
}

char LowerAssert::ID = 0;

Pass *createLowerAssertPass() { return new LowerAssert(); }

} // namespace seahorn
