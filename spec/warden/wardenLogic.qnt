// -*- mode: Bluespec; -*-
// wardenLogic.qnt: the pure logic of the warden/broker approval-and-mint
// protocol (research/agent-platform WARDEN.md v2, IDENTITY.md, CONTROL-PLANE.md,
// HARNESS.md). Types, the design's numbers, the caller rules (one `Rules`
// record: every unsafe choice is a named mutant beside the design), and the
// guards and updates each party applies. No distributed state here: the
// Choreo wrapper is warden.qnt, the instances and scripted runs wardenTest.qnt.
//
// Time: 1 tick = 5 minutes.
module wardenLogic {
  import basicSpells.* from "./spells/basicSpells"

  // ---------------------------------------------------------------- numbers
  pure val JWT_LIFE = 1      // yard-ctl STS JWT lives at most 5 min (IDENTITY.md; the signer forces exp - iat <= 5 min)
  pure val SESSION = 3       // AWS session 900 s (WARDEN 2.2); also AWS's minimum DurationSeconds, so it cannot be shortened
  pure val REMINT = 2        // the broker re-mints every 10 min while the grant is live (WARDEN 4 step 8)
  pure val CARD_EXP = 3      // unanswered requests expire after 15 min (WARDEN 5)
  pure val PASSKEY_FRESH = 1 // 5 min, judged when the decision reaches the warden (decision 4, 2026-10-07)
  pure val MAX_TTL = 6       // the class maximum TTL, scaled to the model (static check, WARDEN 4 step 5)
  pure val MAX_TIME = 14     // the model's horizon
  pure val MAX_SENDS = 3     // requests and withdrawals one sandbox may send
  pure val MAX_JWT_REQS = 8  // JWT requests the broker may make
  pure val MAX_RESTARTS = 1  // broker crashes
  pure val CT_LAG = 3        // ASSUMED 15 min, to measure on the sandbox account: CloudTrail delivery, the reconciler's settle bound
  pure val MAX_MINTS_PER_GRANT = 3 // ASSUMED (accepted 2026-10-07): renewal and IP-change re-mints share a per-grant cap of 3
  pure val MAX_PULLS = 2     // epoch pulls the broker may make (start and reconnect)
  pure val MAX_EPOCH = 1     // suspend/resume cycles per sandbox (SR0: the credential epoch moves at suspend)
  pure val MAX_IP_CHANGES = 1

  // ---------------------------------------------------------------- domains
  type Sbx = str
  type Pol = str             // "ro" (low tier), "iam" (iam-lite: elevated, passkey), "admin" (fails the static checks)
  pure val SBXS = Set("sbxA", "sbxB")
  pure val REQS = Set(1, 2)
  pure val POLS = Set("ro", "iam", "admin")
  pure val REGIONS = Set("r1", "r2")
  pure val TTLS = Set(4, 6)

  // The rendered card: everything the approval binds. pol stands for the
  // policy bytes (inline policy, PolicyArns, tags), region for scope
  // (account/region), sbx for the principal (RoleSessionName, yard-sandbox
  // tag, JWT sub), ttl for the requested TTL; ver is the request's version
  // (a re-request with other parameters is a new version).
  type Content = { sbx: Sbx, req: int, ver: int, pol: Pol, region: str, ttl: int }
  // policy_sha: an injective hash (h1 == h2 iff the contents are equal)
  type Hash = { of: Content }
  pure def hash(c: Content): Hash = { of: c }
  // escalation / elevated class: iam-lite (decision 4: always per task) needs a passkey (decision 7)
  pure def isEsc(c: Content): bool = c.pol == "iam"
  // the mechanical checks block before any card is shown (deny list, TTL <= class max)
  pure def blocked(c: Content): bool = c.pol == "admin" or c.ttl > MAX_TTL

  type CardKey = { sbx: Sbx, req: int }
  type Intent = { pol: Pol, region: str, ttl: int }
  type CardStatus = Pending | Approved | Denied | Withdrawn | Blocked
  type Card = { content: Content, status: CardStatus, createdAt: int }
  // a passkey assertion over a challenge the warden issued at chAt for hash h
  type Asr = { h: Hash, chAt: int }
  type Grant = { h: Hash, content: Content, key: CardKey, start: int, end: int, revokedAt: int }
  // the JWT the broker presents, plus the rendered session policy that travels
  // with it; h is the approval's policy_sha (session tags yard-apv and
  // yard-psha), epoch the session's credential epoch (SR0), ip the home-IP
  // generation it was minted for
  type Jwt = { id: int, sbx: Sbx, h: Hash, slot: int, ip: int, epoch: int, exp: int, policy: Content }
  type Cred = { id: int, h: Hash, sbx: Sbx, policy: Content, slot: int, ip: int, epoch: int, issuedAt: int, exp: int }
  type Secret = CloudCred(int) | Surrogate(int) | JwtTok(int)
  type Attempt = { att: int, jwt: Jwt }
  type Decision = { key: CardKey, h: Hash, approve: bool, ttl: int, clickAt: int, asr: Option[Asr] }

  // ---------------------------------------------------------------- caller rules
  type RetryRule = NextSlot | BlindRetry | WaitForAnswer
  type Inject = AwsEcs | AzureSurrogate
  type EndRule = FenceAtMint | CheckAtRequest | WhileLive
  type CutoffRule = CutoffAfterSettle | CutoffAtRevoke
  type ExpiryRule = AtArrival | AtClick
  // SR0 session phase in yard-ctl
  type SessPhase = SActive | SSuspended | SResuming
  type Rules = {
    hashBound: bool,        // the approval carries policy_sha and the warden matches it
    mintFromApproved: bool, // the mint renders the approved bytes, not the card's current content by id
    editsSupersede: bool,   // a re-request is a new card version; false: the card is edited in place
    retry: RetryRule,       // broker rule for an unanswered AssumeRole
    passkeyBound: bool,     // the assertion's challenge is bound to this card's hash
    passkeyFresh: bool,     // the assertion is at most PASSKEY_FRESH old when the warden accepts it
    inject: Inject,         // what the broker hands the VM
    rawForward: bool,       // surrogate mode, but the broker forwards the real token
    forwardJwt: bool,       // the broker hands the VM the STS JWT (the az --federated-token path)
    ttlClamp: bool,         // the grant ends at the approved (possibly shorter) TTL
    endRule: EndRule,       // how a mint is kept inside the grant window
    cutoff: CutoffRule,     // the aws:TokenIssueTime cutoff on revoke
    expiryAt: ExpiryRule,   // card expiry dated at the warden's arrival or at the page's click
    draftApproves: bool,    // a low-tier draft counts as approval
    replayExtends: bool,    // a duplicate approval restarts the grant
    trustClaimed: bool,     // the broker believes the sandbox id the request names, not the tap
    sessionTemplate: bool,  // the "approve this template for the session" button exists
    revokeOnSupersede: bool,// a withdraw, or the approval of a newer version, revokes the task's old grant
    epochCheck: bool,       // the broker refuses a JWT or credential of a stale session epoch
    reconciler: bool,       // a CloudTrail reconciler records mints nobody heard about
    orphanRevoke: bool,     // ... and revokes them (a deny on the mint's own session tag)
    brokerAck: bool,        // a resume completes only once the broker acknowledges the new epoch
  }

  // The design: WARDEN.md v2 with the decisions of 2026-10-07 (README
  // "Findings, and the decisions of 2026-10-07").
  pure val DESIGN_AWS: Rules = {
    hashBound: true, mintFromApproved: true, editsSupersede: true, retry: NextSlot,
    passkeyBound: true, passkeyFresh: true, inject: AwsEcs, rawForward: false,
    forwardJwt: false, ttlClamp: true, endRule: FenceAtMint, cutoff: CutoffAfterSettle,
    expiryAt: AtArrival, draftApproves: false, replayExtends: false, trustClaimed: false,
    sessionTemplate: false, revokeOnSupersede: true, epochCheck: true, reconciler: true,
    orphanRevoke: true, brokerAck: true,
  }
  pure val DESIGN_AZURE: Rules = { ...DESIGN_AWS, inject: AzureSurrogate }

  // ---------------------------------------------------------------- warden (in yard-ctl)
  // intake: the card a request renders to (drafting = picking the template and
  // filling parameters; the agent's own choice of intent already ranges over
  // every template, so an injected drafter adds no behaviour here)
  pure def nextContent(cards: CardKey -> Card, key: CardKey, i: Intent): Content = {
    val ver = if (cards.has(key)) cards.get(key).content.ver + 1 else 1
    { sbx: key.sbx, req: key.req, ver: ver, pol: i.pol, region: i.region, ttl: i.ttl }
  }

  pure def expired(r: Rules, card: Card, d: Decision, now: int): bool =
    if (r.expiryAt == AtArrival) now > card.createdAt + CARD_EXP
    else d.clickAt > card.createdAt + CARD_EXP

  // decision 5 (2026-10-07): the approved content is the card with the
  // approved TTL; "approve with a shorter TTL" re-hashes, and the decision
  // and the passkey bind the new hash
  pure def finalContent(c: Content, ttl: int): Content = { ...c, ttl: ttl }

  // decision 4: per card, a single-use challenge the warden issued, fresh
  // for 5 min when the decision reaches the warden, over the final hash
  pure def passkeyOk(r: Rules, card: Card, d: Decision, now: int, issued: Set[Asr], used: Set[Asr]): bool =
    not(isEsc(card.content)) or (match d.asr {
      | Some(a) => and {
          issued.contains(a), not(used.contains(a)),
          r.passkeyBound implies a.h == hash(finalContent(card.content, d.ttl)),
          r.passkeyFresh implies now - a.chAt <= PASSKEY_FRESH,
        }
      | None => false
    })

  // why an approval is refused, "" when it is accepted
  pure def refusal(r: Rules, card: Card, d: Decision, now: int, issued: Set[Asr], used: Set[Asr]): str =
    if (card.status != Pending) "status"
    else if (r.hashBound and d.h != hash(finalContent(card.content, d.ttl))) "hash"
    else if (expired(r, card, d, now)) "expired"
    else if (d.ttl > card.content.ttl) "ttl"
    else if (not(passkeyOk(r, card, d, now, issued, used))) "passkey"
    else ""

  pure def newGrant(r: Rules, card: Card, key: CardKey, ttl: int, now: int): Grant = {
    val c = finalContent(card.content, ttl)
    { h: hash(c), content: c, key: key, start: now,
      end: now + (if (r.ttlClamp) ttl else card.content.ttl), revokedAt: -1 }
  }

  // the replayExtends mutant: a duplicate approval of an approved card restarts its grant
  pure def replays(r: Rules, card: Card, d: Decision, grants: Hash -> Grant): bool = and {
    r.replayExtends, d.approve, card.status == Approved, d.h == hash(finalContent(card.content, d.ttl)), grants.has(d.h),
  }

  // ---------------------------------------------------------------- yard-ctl STS
  pure def slotOf(g: Grant, now: int): int = (now - g.start) / REMINT

  // may the STS sign a JWT for grant g now (one per grant, 10-min slot and
  // home-IP generation, at most MAX_MINTS_PER_GRANT in all), and with which expiry
  pure def mintable(r: Rules, g: Grant, issued: Set[(Hash, int, int)], now: int, ip: int): bool = and {
    g.revokedAt < 0, now >= g.start,
    not(issued.contains((g.h, slotOf(g, now), ip))),
    issued.filter(k => k._1 == g.h).size() < MAX_MINTS_PER_GRANT,
    if (r.endRule == WhileLive) now < g.end else now <= g.end - SESSION,
  }
  pure def jwtExp(r: Rules, g: Grant, now: int): int =
    if (r.endRule == FenceAtMint) min(now + JWT_LIFE, g.end - SESSION) else now + JWT_LIFE

  // what the mint renders: the approved bytes, or (mutant) the card's current content
  pure def renderForMint(r: Rules, g: Grant, cards: CardKey -> Card): Content =
    if (r.mintFromApproved or not(cards.has(g.key))) g.content else cards.get(g.key).content

  pure def denyCutoff(r: Rules, revokedAt: int): int =
    if (r.cutoff == CutoffAfterSettle) revokedAt + JWT_LIFE else revokedAt

  // ---------------------------------------------------------------- cloud STS
  pure def mint(j: Jwt, att: int, now: int): Cred =
    { id: att, h: j.h, sbx: j.sbx, policy: j.policy, slot: j.slot, ip: j.ip, epoch: j.epoch, issuedAt: now, exp: now + SESSION }
  // aws:TokenIssueTime deny: a credential issued at or before the cutoff is
  // refused; an orphan's deny names its own mint (session tag yard-mint)
  pure def usable(c: Cred, deny: Hash -> int, orphanDeny: Set[int], now: int): bool =
    now < c.exp and not(deny.has(c.h) and c.issuedAt <= deny.get(c.h)) and not(orphanDeny.contains(c.id))

  // ---------------------------------------------------------------- broker
  pure def subjectOf(r: Rules, tap: Sbx, claimed: Sbx): Sbx = if (r.trustClaimed) claimed else tap
  pure def secretFor(r: Rules, c: Cred): Secret =
    if (r.inject == AwsEcs or r.rawForward) CloudCred(c.id) else Surrogate(c.id)
  // the broker may drop an unanswered attempt: design only once no copy can
  // land (the JWT has expired: AWS refuses it after exp, the settle bound)
  pure def mayDrop(r: Rules, a: Attempt, now: int): bool = match r.retry {
    | NextSlot => now > a.jwt.exp
    | BlindRetry => true
    | WaitForAnswer => false
  }
}
