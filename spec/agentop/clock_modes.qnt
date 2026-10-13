// -*- mode: Bluespec; -*-
// clock_modes: the design, and one mutant per rule of clock.qnt.
module cdesign {
  import clock(RULES = { persist: true, ahead: true }).* from "./clock"
}
// processClock: persist off -> runsOnce (a restart resets Yard-Time; a pruned attempt's late copy is accepted again)
module processClock {
  import clock(RULES = { persist: false, ahead: true }).* from "./clock"
}
// ceilingBehind: ahead off -> runsOnce (the persisted ceiling lags the times handed out)
module ceilingBehind {
  import clock(RULES = { persist: true, ahead: false }).* from "./clock"
}
