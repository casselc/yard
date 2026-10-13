// -*- mode: Bluespec; -*-
// broker_modes: the design, and one mutant per rule of broker.qnt.
module bdesign {
  import broker(RULES = { atomic: true, durable: true, hold: true, pinned: true, tokens: true, honest: true }).* from "./broker"
}
// checkConfirmedOnly: atomic off -> withinTokens (concurrent reservations pass the limit together)
module checkConfirmedOnly {
  import broker(RULES = { atomic: false, durable: true, hold: true, pinned: true, tokens: true, honest: true }).* from "./broker"
}
// volatileReserve: durable off -> accounted (a crash forgets a sent call the provider then serves)
module volatileReserve {
  import broker(RULES = { atomic: true, durable: false, hold: true, pinned: true, tokens: true, honest: true }).* from "./broker"
}
// dropUnanswered: hold off -> accounted (a lost answer is released at zero)
module dropUnanswered {
  import broker(RULES = { atomic: true, durable: true, hold: false, pinned: true, tokens: true, honest: true }).* from "./broker"
}
// valuationFromGraph: pinned off -> withinMoney (the agent zeroed the price its limit is enforced with)
module valuationFromGraph {
  import broker(RULES = { atomic: true, durable: true, hold: true, pinned: false, tokens: true, honest: true }).* from "./broker"
}
// moneyOnly: tokens off -> withinTokens (the local route costs no money)
module moneyOnly {
  import broker(RULES = { atomic: true, durable: true, hold: true, pinned: true, tokens: false, honest: true }).* from "./broker"
}
// claimExact: honest off -> exactIsExact
module claimExact {
  import broker(RULES = { atomic: true, durable: true, hold: true, pinned: true, tokens: true, honest: false }).* from "./broker"
}
