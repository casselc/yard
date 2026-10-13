// -*- mode: Bluespec; -*-
// executor_modes: the design, and one mutant per rule of executor.qnt.
module edesign {
  import executor(RULES = { fence: true, alloc: true, stopped: true, revoke: true, capture: true }).* from "./executor"
}
// restartStartsAgain: fence off -> oneLive (a late start of the abandoned allocation runs beside the new one)
module restartStartsAgain {
  import executor(RULES = { fence: false, alloc: true, stopped: true, revoke: true, capture: true }).* from "./executor"
}
// bindByCid: alloc off -> attributed (a fenced worker's calls land on the next attempt with the same CID)
module bindByCid {
  import executor(RULES = { fence: true, alloc: false, stopped: true, revoke: true, capture: true }).* from "./executor"
}
// unreachableIsStopped: stopped off -> stoppedIsStopped
module unreachableIsStopped {
  import executor(RULES = { fence: true, alloc: true, stopped: false, revoke: true, capture: true }).* from "./executor"
}
// endBeforeRevoke: revoke off -> noSpendAfterFinal
module endBeforeRevoke {
  import executor(RULES = { fence: true, alloc: true, stopped: true, revoke: false, capture: true }).* from "./executor"
}
// captureFromUnstopped: capture off -> candidateStable
module captureFromUnstopped {
  import executor(RULES = { fence: true, alloc: true, stopped: true, revoke: true, capture: false }).* from "./executor"
}
