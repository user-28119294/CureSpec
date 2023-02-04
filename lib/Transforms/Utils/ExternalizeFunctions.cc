/* Externalize functions selected by command line */

#include "llvm/ADT/Optional.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/raw_ostream.h"

#include "seahorn/Support/SeaDebug.h"
#include "seahorn/Support/SeaLog.hh"

using namespace llvm;

#define EXTERN_FUNCTIONS_USE_REGEX

static llvm::cl::list<std::string>
    ExternalizeFunctionNames("externalize-function",
                             llvm::cl::desc("Set the linkage to external"),
                             llvm::cl::ZeroOrMore, llvm::cl::CommaSeparated);

static llvm::cl::opt<bool>
    RemoveBodies("externalize-functions-delete",
                 llvm::cl::desc("Delete bodies of externalized functions"),
                 llvm::cl::init(true));

namespace seahorn {

class ExternalizeFunctions : public ModulePass {

#ifdef EXTERN_FUNCTIONS_USE_REGEX
  struct MatchRegex : public std::unary_function<Function *, bool> {
    llvm::Optional<llvm::Regex> m_re;
    MatchRegex(std::string s) {
      if (s != "") {
        m_re = llvm::Regex(s);
        std::string Error;
        if (!m_re->isValid(Error)) {
          WARN << "Syntax error in regex '" << s << "' " << Error;
          m_re = llvm::None;
        }
      }
    }
    bool operator()(Function *F) { return m_re && m_re->match(F->getName()); }
  };
#endif

public:
  static char ID;

  ExternalizeFunctions() : ModulePass(ID) {}

  virtual bool runOnModule(Module &M) {
    if (ExternalizeFunctionNames.begin() == ExternalizeFunctionNames.end())
      return false;

    SmallPtrSet<Function *, 16> externalizeFunctions;
    for (auto name : ExternalizeFunctionNames) {
#ifndef EXTERN_FUNCTIONS_USE_REGEX
      if (Function *F = M.getFunction(name))
        externalizeFunctions.insert(F);
#else
      MatchRegex filter(name);
      for (auto &F : M) {
        if (filter(&F)) {
          externalizeFunctions.insert(&F);
        }
      }
#endif
    }

    bool Change = false;
    // Delete function bodies and set external linkage
    for (Function &F : M) {
      if (F.isDeclaration() || externalizeFunctions.count(&F) == 0)
        continue;
      LOG("extern",
          errs() << "EXTERNALIZING " << llvm::demangle(F.getName()) << "\n");
      Change = true;

      if (!RemoveBodies && F.hasLocalLinkage()) {
        // in C++ local names are mangled with _ZL prefix, as we make functions
        // external, also rename
        auto name = F.getName();
        if (name.startswith("_ZL") && name.size() > 3) {
          F.setName("_Z" + name.substr(3));
          LOG("extern",
              errs() << "Renaming: " << name << " to " << F.getName() << "\n";);
        }
        // -- change linkage to external
        F.setLinkage(GlobalValue::ExternalLinkage);
        LOG("extern", errs() << "linkage of " << F.getName()
                             << " is set to external: "
                             << F.hasExternalLinkage() << "\n";);
      } else {
        F.deleteBody();
        F.setComdat(nullptr);
      }
    }

    // get rid of aliases, even if the function has not been removed

    // Delete global aliases: aliases cannot point to a function
    // declaration so if there is an alias to an external function
    // we also need to remove all its aliases.
    std::vector<GlobalAlias *> aliases;
    for (GlobalAlias &GA : M.aliases()) {
      aliases.push_back(&GA);
    }

    for (GlobalAlias *GA : aliases) {
      if (Function *aliasee = dyn_cast<Function>(GA->getAliasee())) {
        if (externalizeFunctions.count(aliasee) > 0) {
          GA->replaceAllUsesWith(aliasee);
          GA->eraseFromParent();
          Change = true;
        }
      }
    }

    LOG("extern-debug", errs() << "Externalize before verify\n\n";);
    llvm::verifyModule(M, &(errs()), nullptr);
    LOG("extern-debug", errs() << "Externalize after verify\n\n";);

    return Change;
  }

  void getAnalysisUsage(AnalysisUsage &AU) { AU.setPreservesAll(); }

  virtual StringRef getPassName() const {
    return "Externalize all selected functions";
  }
};

char ExternalizeFunctions::ID = 0;

Pass *createExternalizeFunctionsPass() { return new ExternalizeFunctions(); }

} // namespace seahorn
