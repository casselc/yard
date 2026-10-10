// -*- mode: Bluespec; -*-
// warden.qnt: the warden/broker approval-and-mint protocol as a Choreo spec.
// Parties: two sandboxes (untrusted agents), the broker (one per node; holds
// the agent's identity, serves the redirected metadata endpoints), yard-ctl
// (the warden module and the yard-ctl STS in one process), the user (the
// tailnet approval page), and the cloud STS (AWS AssumeRoleWithWebIdentity,
// or Entra's equivalent).
//
// Network: Choreo's per-recipient message sets. A message stays in its
// recipient's set until `loseMessage` removes it, so delivery may be delayed
// arbitrarily, reordered, repeated (a handler meets it again) or lost.
// Every cross-boundary call is request, late effect, lost answer and
// duplicate delivery (casselc/observability otel-chdb/model/TEMPLATE.md):
// see README.md "Ambiguity register".
//
// The pure logic is in wardenLogic.qnt; instances and scripted runs are in
// wardenTest.qnt; run.sh runs the table.
module warden {
  import basicSpells.* from "./spells/basicSpells"
  import wardenLogic.* from "./wardenLogic"
  import choreo(processes = NODES) as choreo from "./choreo"

  const RULES: Rules

  pure val BROKER = "broker"
  pure val CTL = "ctl"
  pure val USER = "user"
  pure val CLOUD = "cloud"
  pure val NODES = SBXS.union(Set(BROKER, CTL, USER, CLOUD))

  // ---------------------------------------------------------------- messages
  type Msg =
    // sandbox -> yard-ctl (POST /warden/requests through the broker; tap-stamped)
    | WReq({ tap: Sbx, req: int, intent: Intent })
    | WWithdraw({ tap: Sbx, req: int })
    // sandbox -> broker (169.254.170.2 / 169.254.169.254, pf rdr; tap-stamped,
    // `claimed` is whatever the agent writes in the request)
    | MetaGet({ tap: Sbx, claimed: Sbx })
    // yard-ctl -> user: the card on the tailnet page (ntfy only links to it)
    | CardMsg({ key: CardKey, h: Hash })
    // user <-> yard-ctl: WebAuthn challenge and the decision
    | ChallengeReq({ h: Hash })
    | ChallengeMsg({ h: Hash, at: int })
    | DecisionMsg(Decision)
    | TemplateOk({ sbx: Sbx, pol: Pol })
    | Abort({ h: Hash })
    // broker <-> yard-ctl STS
    | JwtReq({ sbx: Sbx, n: int, ip: int })
    | JwtMsg(Jwt)
    | Revoke({ h: Hash })
    | MintAudit({ id: int })            // warden.mint: the broker heard a mint
    | EpochNotice({ sbx: Sbx, epoch: int }) // SR0: resume tells the broker the session's new credential epoch
    | EpochAck({ sbx: Sbx, epoch: int })    // ... and the broker acknowledges it (resume waits for this)
    | EpochPull({ n: int })                 // broker start or reconnect: read every session's current epoch
    | EpochState({ n: int, epochs: Sbx -> int })
    | OrphanDeny({ id: int })               // decision 12 + 2026-10-07 round 3: revoke an orphan by its own mint tag
    | OrphanDenyOk({ id: int })
    // broker <-> cloud STS
    | AssumeRole(Attempt)
    | CredsMsg({ att: int, cred: Cred })
    | MintErr({ att: int })       // an error answer, sent after the mint applied
    | MintRejected({ att: int })  // ExpiredToken: definite "not done" for this copy
    // yard-ctl <-> cloud: the aws:TokenIssueTime deny (PutRolePolicy)
    | DenyBefore({ h: Hash, cutoff: int })
    | DenyOk({ h: Hash, cutoff: int })
    // broker -> sandbox: the metadata endpoint's answer
    | CredResp({ secret: Secret })

  // ---------------------------------------------------------------- local state (one record for every role)
  type StateFields = {
    // sandbox
    sent: int,
    // yard-ctl: warden + STS
    cards: CardKey -> Card,
    grants: Hash -> Grant,
    handled: Set[Msg],
    issued: Set[(Hash, int, int)],// (grant, 10-min slot, home-IP generation) with a JWT signed: create-only in SQLite
    jwtN: int,
    templateOk: Set[(Sbx, Pol)],
    denyOk: Set[Hash],
    refused: Set[str],
    chIssued: Set[Asr],           // passkey challenges the warden issued ...
    chUsed: Set[Asr],             // ... and those already redeemed (single-use)
    epoch: Sbx -> int,            // the session row's credential epoch (SR0)
    audited: Set[int],            // warden.mint rows (the broker heard the mint)
    orphans: Set[int],            // mints found only by the CloudTrail reconciler
    orphanDenyOk: Set[int],       // ... whose revoke the cloud confirmed
    sess: Sbx -> SessPhase,       // SR0 session phase
    // user
    decided: Set[Hash],
    asked: Set[Hash],
    approved: Set[Hash],
    aborted: Set[Hash],
    // broker
    pend: Set[Attempt],
    held: Set[Cred],
    served: Set[(Sbx, int)],
    usedJwt: Set[int],
    answered: Set[int],
    timedOut: Set[int],
    revoked: Set[Hash],
    nReq: int,
    lastReqAt: int,
    nAtt: int,
    restarts: int,
    epochSeen: Sbx -> int,        // the newest credential epoch the broker knows per sandbox
    ipSeen: int,                  // the home-IP generation the broker last saw
    staleRefused: int,
    staleExchanged: int,          // JWTs exchanged although their epoch was stale (only the mutant)
    synced: bool,                 // the broker has read the epochs since it (re)started
    pulls: int,
    // cloud
    minted: Set[Cred],
    done: Set[int],
    deny: Hash -> int,
    orphanDeny: Set[int],
  }

  // ghost record of what happened, for the invariants (never read by a party)
  type GrantLog = { h: Hash, at: int, end: int, asr: Option[Asr], seq: int, viaUser: bool }
  // a card version (the hash also covers the approved TTL)
  type CardId = { sbx: Sbx, req: int, ver: int }
  pure def cid(c: Content): CardId = { sbx: c.sbx, req: c.req, ver: c.ver }
  type TrailEvent = { id: int, h: Hash, at: int }
  type Ghost =
    | Shown({ c: CardId, at: int })
    | Granted(GrantLog)
    | Dead(CardId)                                // denied, withdrawn or superseded
    | Trail(TrailEvent)                           // CloudTrail AssumeRoleWithWebIdentity (tags yard-apv, yard-psha)
    | UserApproved({ h: Hash, ttl: int, at: int })
    | UserTemplate({ sbx: Sbx, pol: Pol })
    | Asserted(Asr)
    | Reveal({ sbx: Sbx, secret: Secret })
  type Extensions = {
    now: int, seq: int,
    shown: Set[{ c: CardId, at: int }],
    granted: Set[GrantLog],
    dead: Set[{ c: CardId, seq: int }],
    trail: Set[TrailEvent],         // CloudTrail: readable by yard-ctl, CT_LAG after the event
    ip: int,                        // the home IP's generation (the environment)
    userApproved: Set[{ h: Hash, ttl: int, at: int }],
    userTemplate: Set[{ sbx: Sbx, pol: Pol }],
    assertions: Set[Asr],
    revealed: Set[{ sbx: Sbx, secret: Secret }],
  }

  /* Boilerplate */
  type Node = str
  type LocalState = choreo::LocalState[Node, StateFields]
  type LocalContext = choreo::LocalContext[Node, StateFields, Msg, (), Extensions]
  type Transition = choreo::Transition[Node, StateFields, Msg, (), Ghost]
  type GlobalContext = choreo::GlobalContext[Node, StateFields, Msg, (), Extensions]
  /* End of boilerplate */

  pure def send(dst: Node, m: Msg): choreo::Effect[Node, Msg, (), Ghost] = choreo::Send({ to: dst, message: m })
  pure def ghost(g: Ghost): choreo::Effect[Node, Msg, (), Ghost] = choreo::CustomEffect(g)

  // ================================================================ sandbox (untrusted)
  // The agent may ask for anything, re-ask with other parameters (an edit)
  // and withdraw. Its SDK polls the metadata endpoint all the time, naming
  // any sandbox it likes: those requests are in the broker's set from the
  // start (init), and stay there (a poll repeats). The tap
  // (epair + mac_ipacl) stamps its real identity; it cannot reach the
  // approval page or yard-ctl except through the broker.
  pure def listen_can_send(ctx: LocalContext): Set[()] =
    if (ctx.state.process_id.in(SBXS) and ctx.state.sent < MAX_SENDS) Set(()) else Set()

  pure def sbx_request(ctx: LocalContext): Set[Transition] =
    tuples(REQS, POLS, REGIONS, TTLS).map(((q, p, rg, t)) => {
      post_state: { ...ctx.state, sent: ctx.state.sent + 1 },
      effects: Set(send(CTL, WReq({ tap: ctx.state.process_id, req: q, intent: { pol: p, region: rg, ttl: t } }))),
    })

  pure def sbx_withdraw(ctx: LocalContext): Set[Transition] =
    REQS.map(q => {
      post_state: { ...ctx.state, sent: ctx.state.sent + 1 },
      effects: Set(send(CTL, WWithdraw({ tap: ctx.state.process_id, req: q }))),
    })

  pure def sbx_listener(ctx: LocalContext): Set[Transition] =
    if (listen_can_send(ctx).size() == 0) Set()
    else Set(sbx_request(ctx), sbx_withdraw(ctx)).flatten()

  // ================================================================ yard-ctl: warden
  pure def unhandled(ctx: LocalContext): Set[Msg] = ctx.messages.filter(m => not(ctx.state.handled.contains(m)))

  pure def listen_intake(ctx: LocalContext): Set[{ tap: Sbx, req: int, intent: Intent }] =
    unhandled(ctx).filterMap(m => match m { | WReq(w) => Some(w) | _ => None })

  // draft, render, check, then show the card (or grant at once in the
  // draftApproves / sessionTemplate variants)
  pure def act_intake(ctx: LocalContext, w: { tap: Sbx, req: int, intent: Intent }): Transition = {
    val st = ctx.state
    val now = ctx.extensions.now
    val key = { sbx: w.tap, req: w.req }
    val content = nextContent(st.cards, key, w.intent)
    val prior = st.cards.has(key)
    val old = if (prior) st.cards.get(key) else { content: content, status: Blocked, createdAt: now }
    val changed = prior and { ...old.content, ver: content.ver } != content
    // the agent changed its request: the old version is superseded (an environment fact)
    val supersedeFx = if (changed and old.status == Pending) Set(ghost(Dead(cid(old.content)))) else Set()
    if (prior and not(changed)) {
      // a duplicate of the same request: nothing new
      { post_state: { ...st, handled: st.handled.setAdd(WReq(w)) }, effects: Set() }
    } else if (prior and not(RULES.editsSupersede)) {
      // mutant: the card is edited in place; its status (Approved included) is kept
      val edited = { ...old.content, pol: content.pol, region: content.region, ttl: content.ttl }
      val card = { ...old, content: edited }
      { post_state: { ...st, handled: st.handled.setAdd(WReq(w)), cards: st.cards.put(key, card) },
        effects: supersedeFx.union(
          if (old.status == Pending) Set(send(USER, CardMsg({ key: key, h: hash(edited) })), ghost(Shown({ c: cid(edited), at: old.createdAt })))
          else Set()) }
    } else if (blocked(content)) {
      { post_state: { ...st, handled: st.handled.setAdd(WReq(w)),
          cards: st.cards.put(key, { content: content, status: Blocked, createdAt: now }) },
        effects: supersedeFx }
    } else {
      val auto = not(isEsc(content)) and (RULES.draftApproves or
                 (RULES.sessionTemplate and st.templateOk.contains((content.sbx, content.pol))))
      val card = { content: content, status: if (auto) Approved else Pending, createdAt: now }
      val g = newGrant(RULES, card, key, content.ttl, now)
      if (auto)
        { post_state: { ...st, handled: st.handled.setAdd(WReq(w)), cards: st.cards.put(key, card),
                        grants: st.grants.put(g.h, g) },
          effects: supersedeFx.union(Set(ghost(Shown({ c: cid(content), at: now })),
            ghost(Granted({ h: g.h, at: now, end: g.end, asr: None, seq: 0, viaUser: false })))) }
      else
        { post_state: { ...st, handled: st.handled.setAdd(WReq(w)), cards: st.cards.put(key, card) },
          effects: supersedeFx.union(Set(send(USER, CardMsg({ key: key, h: hash(content) })),
                                         ghost(Shown({ c: cid(content), at: now })))) }
    }
  }

  // revoke grants: stop signing, tell the broker, apply the TokenIssueTime
  // deny scoped to the task's session tag (decision 2, 2026-10-07)
  pure def revoked(gs: Hash -> Grant, hs: Set[Hash], now: int): Hash -> Grant =
    gs.keys().mapBy(h => if (hs.contains(h)) { ...gs.get(h), revokedAt: now } else gs.get(h))
  pure def revokeFx(hs: Set[Hash], now: int): Set[choreo::Effect[Node, Msg, (), Ghost]] =
    hs.map(h => Set(send(BROKER, Revoke({ h: h })), send(CLOUD, DenyBefore({ h: h, cutoff: denyCutoff(RULES, now) })))).flatten()
  // the task's live grants other than `keep` (decision 10: superseded or withdrawn)
  pure def liveOfTask(gs: Hash -> Grant, key: CardKey, keep: Set[Hash]): Set[Hash] =
    if (not(RULES.revokeOnSupersede)) Set()
    else gs.keys().filter(h => gs.get(h).key == key and gs.get(h).revokedAt < 0 and not(keep.contains(h)))

  pure def listen_withdraw(ctx: LocalContext): Set[{ tap: Sbx, req: int }] =
    unhandled(ctx).filterMap(m => match m { | WWithdraw(w) => Some(w) | _ => None })

  pure def act_withdraw(ctx: LocalContext, w: { tap: Sbx, req: int }): Transition = {
    val st = ctx.state
    val key = { sbx: w.tap, req: w.req }
    val live = st.cards.has(key) and (st.cards.get(key).status == Pending or st.cards.get(key).status == Approved)
    val hs = liveOfTask(st.grants, key, Set())
    { post_state: { ...st, handled: st.handled.setAdd(WWithdraw(w)),
        cards: if (live) st.cards.put(key, { ...st.cards.get(key), status: Withdrawn }) else st.cards,
        grants: revoked(st.grants, hs, ctx.extensions.now) },
      effects: (if (live) Set(ghost(Dead(cid(st.cards.get(key).content)))) else Set()).union(revokeFx(hs, ctx.extensions.now)) }
  }

  pure def listen_challenge_req(ctx: LocalContext): Set[Hash] =
    unhandled(ctx).filterMap(m => match m { | ChallengeReq(c) => Some(c.h) | _ => None })

  pure def act_challenge(ctx: LocalContext, h: Hash): Transition =
    { post_state: { ...ctx.state, handled: ctx.state.handled.setAdd(ChallengeReq({ h: h })),
                    chIssued: ctx.state.chIssued.setAdd({ h: h, chAt: ctx.extensions.now }) },
      effects: Set(send(USER, ChallengeMsg({ h: h, at: ctx.extensions.now }))) }

  // decisions are not marked handled: a duplicate delivery meets the handler again
  pure def listen_decision(ctx: LocalContext): Set[Decision] =
    ctx.messages.filterMap(m => match m { | DecisionMsg(d) => Some(d) | _ => None })
      .filter(d => ctx.state.cards.has(d.key))

  pure def act_decision(ctx: LocalContext, d: Decision): Transition = {
    val st = ctx.state
    val now = ctx.extensions.now
    val card = st.cards.get(d.key)
    val why = refusal(RULES, card, d, now, st.chIssued, st.chUsed)
    if (replays(RULES, card, d, st.grants)) {
      val g = newGrant(RULES, card, d.key, d.ttl, now)
      { post_state: { ...st, grants: st.grants.put(g.h, g) },
        effects: Set(ghost(Granted({ h: g.h, at: now, end: g.end, asr: d.asr, seq: 0, viaUser: true }))) }
    } else if (why != "") {
      { post_state: { ...st, refused: st.refused.setAdd(why) }, effects: Set() }
    } else if (not(d.approve)) {
      { post_state: { ...st, cards: st.cards.put(d.key, { ...card, status: Denied }) },
        effects: Set(ghost(Dead(cid(card.content)))) }
    } else {
      val g = newGrant(RULES, card, d.key, d.ttl, now)
      val old = liveOfTask(st.grants, d.key, Set(g.h))
      { post_state: { ...st, cards: st.cards.put(d.key, { ...card, status: Approved }),
                      grants: revoked(st.grants, old, now).put(g.h, g),
                      chUsed: match d.asr { | Some(a) => st.chUsed.setAdd(a) | None => st.chUsed } },
        effects: revokeFx(old, now).union(Set(ghost(Granted({ h: g.h, at: now, end: g.end, asr: d.asr, seq: 0, viaUser: true })))) }
    }
  }

  pure def listen_template(ctx: LocalContext): Set[(Sbx, Pol)] =
    ctx.messages.filterMap(m => match m { | TemplateOk(t) => Some((t.sbx, t.pol)) | _ => None })
      .filter(t => not(ctx.state.templateOk.contains(t)))

  pure def act_template(ctx: LocalContext, t: (Sbx, Pol)): Transition =
    { post_state: { ...ctx.state, templateOk: ctx.state.templateOk.setAdd(t) }, effects: Set() }

  // revoke (warden.revoke): stop signing, tell the broker, apply the TokenIssueTime deny
  pure def listen_abort(ctx: LocalContext): Set[Hash] =
    ctx.messages.filterMap(m => match m { | Abort(a) => Some(a.h) | _ => None })
      .filter(h => ctx.state.grants.has(h) and ctx.state.grants.get(h).revokedAt < 0)

  pure def act_abort(ctx: LocalContext, h: Hash): Transition = {
    val now = ctx.extensions.now
    { post_state: { ...ctx.state, grants: revoked(ctx.state.grants, Set(h), now) }, effects: revokeFx(Set(h), now) }
  }

  // idempotent retry of the deny until the cloud confirms it
  pure def listen_deny_unconfirmed(ctx: LocalContext): Set[Hash] =
    ctx.state.grants.keys().filter(h => ctx.state.grants.get(h).revokedAt >= 0 and not(ctx.state.denyOk.contains(h)))

  pure def act_resend_deny(ctx: LocalContext, h: Hash): Transition =
    { post_state: ctx.state,
      effects: Set(send(CLOUD, DenyBefore({ h: h, cutoff: denyCutoff(RULES, ctx.state.grants.get(h).revokedAt) }))) }

  pure def listen_deny_ok(ctx: LocalContext): Set[Hash] =
    ctx.messages.filterMap(m => match m { | DenyOk(d) => Some(d.h) | _ => None })
      .filter(h => not(ctx.state.denyOk.contains(h)))

  pure def act_deny_ok(ctx: LocalContext, h: Hash): Transition =
    { post_state: { ...ctx.state, denyOk: ctx.state.denyOk.setAdd(h) }, effects: Set() }

  // ================================================================ yard-ctl: STS
  pure def listen_jwt_req(ctx: LocalContext): Set[{ sbx: Sbx, n: int, ip: int }] =
    unhandled(ctx).filterMap(m => match m { | JwtReq(q) => Some(q) | _ => None })

  // sign a JWT for one mintable grant of the sandbox the request names, or
  // answer nothing (the broker does not wait on it: the next MetaGet asks again)
  pure def act_jwt(ctx: LocalContext, q: { sbx: Sbx, n: int, ip: int }): Set[Transition] = {
    val st = ctx.state
    val now = ctx.extensions.now
    val gs = st.grants.values().filter(g => g.content.sbx == q.sbx and mintable(RULES, g, st.issued, now, q.ip))
    val none = { post_state: { ...st, handled: st.handled.setAdd(JwtReq(q)) }, effects: Set() }
    if (gs.size() == 0) Set(none)
    else gs.map(g => {
      val j = { id: st.jwtN, sbx: q.sbx, h: g.h, slot: slotOf(g, now), ip: q.ip, epoch: st.epoch.get(q.sbx),
                exp: jwtExp(RULES, g, now), policy: renderForMint(RULES, g, st.cards) }
      { post_state: { ...st, handled: st.handled.setAdd(JwtReq(q)), issued: st.issued.setAdd((g.h, j.slot, j.ip)),
                      jwtN: st.jwtN + 1 },
        effects: Set(send(BROKER, JwtMsg(j))) }
    })
  }

  // SR0: a suspend commits and moves the session's credential epoch
  pure def listen_suspend(ctx: LocalContext): Set[Sbx] =
    SBXS.filter(x => ctx.state.sess.get(x) == SActive and ctx.state.epoch.get(x) < MAX_EPOCH)
  pure def act_suspend(ctx: LocalContext, x: Sbx): Transition =
    { post_state: { ...ctx.state, epoch: ctx.state.epoch.set(x, ctx.state.epoch.get(x) + 1), sess: ctx.state.sess.set(x, SSuspended) },
      effects: Set() }

  // resume tells the broker the new epoch and completes only on its
  // acknowledgement (2026-10-07, round 3): request, effect, answer, each of
  // which may be lost, late or repeated; unacknowledged, it re-sends
  pure def listen_resume(ctx: LocalContext): Set[Sbx] = SBXS.filter(x => ctx.state.sess.get(x) == SSuspended)
  pure def act_resume(ctx: LocalContext, x: Sbx): Transition =
    { post_state: { ...ctx.state, sess: ctx.state.sess.set(x, if (RULES.brokerAck) SResuming else SActive) },
      effects: Set(send(BROKER, EpochNotice({ sbx: x, epoch: ctx.state.epoch.get(x) }))) }
  pure def listen_resuming(ctx: LocalContext): Set[Sbx] = SBXS.filter(x => ctx.state.sess.get(x) == SResuming)
  pure def act_resend_notice(ctx: LocalContext, x: Sbx): Transition =
    { post_state: ctx.state, effects: Set(send(BROKER, EpochNotice({ sbx: x, epoch: ctx.state.epoch.get(x) }))) }
  pure def listen_epoch_ack(ctx: LocalContext): Set[Sbx] =
    ctx.messages.filterMap(m => match m { | EpochAck(a) => Some(a) | _ => None })
      .filter(a => ctx.state.sess.get(a.sbx) == SResuming and a.epoch == ctx.state.epoch.get(a.sbx)).map(a => a.sbx)
  pure def act_epoch_ack(ctx: LocalContext, x: Sbx): Transition =
    { post_state: { ...ctx.state, sess: ctx.state.sess.set(x, SActive) }, effects: Set() }
  // the broker's pull, answered with every session's current epoch
  pure def listen_pull(ctx: LocalContext): Set[int] =
    unhandled(ctx).filterMap(m => match m { | EpochPull(q) => Some(q.n) | _ => None })
  pure def act_pull(ctx: LocalContext, n: int): Transition =
    { post_state: { ...ctx.state, handled: ctx.state.handled.setAdd(EpochPull({ n: n })) },
      effects: Set(send(BROKER, EpochState({ n: n, epochs: ctx.state.epoch }))) }

  pure def listen_mint_audit(ctx: LocalContext): Set[int] =
    ctx.messages.filterMap(m => match m { | MintAudit(a) => Some(a.id) | _ => None })
      .filter(i => not(ctx.state.audited.contains(i)))
  pure def act_mint_audit(ctx: LocalContext, i: int): Transition =
    { post_state: { ...ctx.state, audited: ctx.state.audited.setAdd(i) }, effects: Set() }

  // decision 12: the CloudTrail reconciler finds a mint with no warden.mint
  // row once the trail has caught up (CT_LAG), and records it as an orphan
  pure def listen_reconcile(ctx: LocalContext): Set[int] =
    if (not(RULES.reconciler)) Set()
    else ctx.extensions.trail.filter(e => and {
      ctx.extensions.now >= e.at + CT_LAG, not(ctx.state.audited.contains(e.id)), not(ctx.state.orphans.contains(e.id)),
    }).map(e => e.id)
  // ... and revokes it: a deny on the mint's own session tag (yard-mint =
  // grant, slot, IP generation), so the task's live session is untouched
  pure def act_reconcile(ctx: LocalContext, i: int): Transition =
    { post_state: { ...ctx.state, orphans: ctx.state.orphans.setAdd(i) },
      effects: if (RULES.orphanRevoke) Set(send(CLOUD, OrphanDeny({ id: i }))) else Set() }
  // idempotent retry of the orphan's deny until the cloud confirms it
  pure def listen_orphan_unconfirmed(ctx: LocalContext): Set[int] =
    if (not(RULES.orphanRevoke)) Set() else ctx.state.orphans.filter(i => not(ctx.state.orphanDenyOk.contains(i)))
  pure def act_resend_orphan_deny(ctx: LocalContext, i: int): Transition =
    { post_state: ctx.state, effects: Set(send(CLOUD, OrphanDeny({ id: i }))) }
  pure def listen_orphan_ok(ctx: LocalContext): Set[int] =
    ctx.messages.filterMap(m => match m { | OrphanDenyOk(o) => Some(o.id) | _ => None })
      .filter(i => not(ctx.state.orphanDenyOk.contains(i)))
  pure def act_orphan_ok(ctx: LocalContext, i: int): Transition =
    { post_state: { ...ctx.state, orphanDenyOk: ctx.state.orphanDenyOk.setAdd(i) }, effects: Set() }

  pure def ctl_listener(ctx: LocalContext): Set[Transition] = Set(
    choreo::cue(ctx, listen_suspend, act_suspend),
    choreo::cue(ctx, listen_resume, act_resume),
    choreo::cue(ctx, listen_resuming, act_resend_notice),
    choreo::cue(ctx, listen_epoch_ack, act_epoch_ack),
    choreo::cue(ctx, listen_pull, act_pull),
    choreo::cue(ctx, listen_orphan_unconfirmed, act_resend_orphan_deny),
    choreo::cue(ctx, listen_orphan_ok, act_orphan_ok),
    choreo::cue(ctx, listen_mint_audit, act_mint_audit),
    choreo::cue(ctx, listen_reconcile, act_reconcile),
    choreo::cue(ctx, listen_intake, act_intake),
    choreo::cue(ctx, listen_withdraw, act_withdraw),
    choreo::cue(ctx, listen_challenge_req, act_challenge),
    choreo::cue(ctx, listen_decision, act_decision),
    choreo::cue(ctx, listen_template, act_template),
    choreo::cue(ctx, listen_abort, act_abort),
    choreo::cue(ctx, listen_deny_unconfirmed, act_resend_deny),
    choreo::cue(ctx, listen_deny_ok, act_deny_ok),
    listen_jwt_req(ctx).map(q => act_jwt(ctx, q)).flatten(),
  ).flatten()

  // ================================================================ user (tailnet approval page)
  pure def cardsShown(ctx: LocalContext): Set[{ key: CardKey, h: Hash }] =
    ctx.messages.filterMap(m => match m { | CardMsg(c) => Some(c) | _ => None })

  pure def listen_undecided(ctx: LocalContext): Set[{ key: CardKey, h: Hash }] =
    cardsShown(ctx).filter(c => not(ctx.state.decided.contains(c.h)))

  pure def challenges(ctx: LocalContext): Set[Asr] =
    ctx.messages.filterMap(m => match m { | ChallengeMsg(x) => Some({ h: x.h, chAt: x.at }) | _ => None })

  // an escalation card's approve button runs WebAuthn, so the page decides
  // one only once it holds a challenge (deny is offered alongside)
  pure def listen_decidable(ctx: LocalContext): Set[{ key: CardKey, h: Hash }] =
    listen_undecided(ctx).filter(c => not(isEsc(c.h.of)) or challenges(ctx).size() > 0)

  // deny, or approve at the card's TTL or shorter: the approval binds the
  // final hash, re-hashed with the approved TTL (decision 5, 2026-10-07); an
  // escalation carries a passkey assertion
  pure def act_decide(ctx: LocalContext, c: { key: CardKey, h: Hash }): Set[Transition] = {
    val st0 = { ...ctx.state, decided: ctx.state.decided.setAdd(c.h) }
    val now = ctx.extensions.now
    // the assertion is over a challenge the page holds: this card's, or
    // (a page bug or a session-wide step-up) another card's or an old one;
    // the warden must check the binding and the age
    val asrs: Set[Option[Asr]] = if (isEsc(c.h.of)) challenges(ctx).map(a => Some(a)) else Set(None)
    val deny = { post_state: st0, effects: Set(send(CTL, DecisionMsg({ key: c.key, h: c.h, approve: false,
                   ttl: c.h.of.ttl, clickAt: now, asr: None }))) }
    val approvals = tuples(TTLS.filter(t => t <= c.h.of.ttl), asrs).map(((t, a)) => {
      val hf = hash(finalContent(c.h.of, t))
      { post_state: { ...st0, approved: st0.approved.setAdd(hf) },
      effects: Set(send(CTL, DecisionMsg({ key: c.key, h: hf, approve: true, ttl: t, clickAt: now, asr: a })),
                   ghost(UserApproved({ h: hf, ttl: t, at: now })))
                 .union(match a { | Some(x) => Set(ghost(Asserted(x))) | None => Set() }) }
    })
    approvals.setAdd(deny)
  }

  // the page asks for a challenge over the final hash (the card at the TTL the user picks)
  pure def listen_need_challenge(ctx: LocalContext): Set[Hash] =
    listen_undecided(ctx).filter(c => isEsc(c.h.of))
      .map(c => TTLS.filter(t => t <= c.h.of.ttl).map(t => hash(finalContent(c.h.of, t)))).flatten()
      .filter(h => not(ctx.state.asked.contains(h)))

  pure def act_ask_challenge(ctx: LocalContext, h: Hash): Transition =
    { post_state: { ...ctx.state, asked: ctx.state.asked.setAdd(h) }, effects: Set(send(CTL, ChallengeReq({ h: h }))) }

  // the session-template button (low tier only), when the design has it
  pure def listen_template_button(ctx: LocalContext): Set[(Sbx, Pol)] =
    if (not(RULES.sessionTemplate)) Set()
    else listen_undecided(ctx).filter(c => not(isEsc(c.h.of))).map(c => (c.h.of.sbx, c.h.of.pol))

  pure def act_template_button(ctx: LocalContext, t: (Sbx, Pol)): Transition =
    { post_state: { ...ctx.state, decided: ctx.state.decided.union(
        listen_undecided(ctx).filter(c => (c.h.of.sbx, c.h.of.pol) == t).map(c => c.h)) },
      effects: Set(send(CTL, TemplateOk({ sbx: t._1, pol: t._2 })), ghost(UserTemplate({ sbx: t._1, pol: t._2 }))) }

  // abort a task the user approved (yardctl / the page)
  pure def listen_abortable(ctx: LocalContext): Set[Hash] =
    ctx.state.approved.filter(h => not(ctx.state.aborted.contains(h)))

  pure def act_abort_button(ctx: LocalContext, h: Hash): Transition =
    { post_state: { ...ctx.state, aborted: ctx.state.aborted.setAdd(h) }, effects: Set(send(CTL, Abort({ h: h }))) }

  pure def user_listener(ctx: LocalContext): Set[Transition] = Set(
    listen_decidable(ctx).map(c => act_decide(ctx, c)).flatten(),
    choreo::cue(ctx, listen_need_challenge, act_ask_challenge),
    choreo::cue(ctx, listen_template_button, act_template_button),
    choreo::cue(ctx, listen_abortable, act_abort_button),
  ).flatten()

  // ================================================================ broker
  pure def metaGets(ctx: LocalContext): Set[{ tap: Sbx, claimed: Sbx }] =
    ctx.messages.filterMap(m => match m { | MetaGet(g) => Some(g) | _ => None })

  // serve a held, unexpired credential for the request's subject to the tap
  pure def listen_servable(ctx: LocalContext): Set[{ tap: Sbx, cred: Cred }] = {
    val now = ctx.extensions.now
    tuples(metaGets(ctx), ctx.state.held).filter(((g, c)) => and {
      ctx.state.synced, c.sbx == subjectOf(RULES, g.tap, g.claimed), now < c.exp, currentEpoch(ctx, c.sbx, c.epoch),
      not(ctx.state.served.contains((g.tap, c.id))),
    }).map(((g, c)) => { tap: g.tap, cred: c })
  }

  pure def act_serve(ctx: LocalContext, x: { tap: Sbx, cred: Cred }): Transition = {
    val sec = secretFor(RULES, x.cred)
    { post_state: { ...ctx.state, served: ctx.state.served.setAdd((x.tap, x.cred.id)) },
      effects: Set(send(x.tap, CredResp({ secret: sec })), ghost(Reveal({ sbx: x.tap, secret: sec }))) }
  }

  // SR0 (branch sr0, internal/issuer): the broker honours only the current
  // credential epoch it knows for the sandbox
  pure def currentEpoch(ctx: LocalContext, x: Sbx, e: int): bool =
    not(RULES.epochCheck) or e >= ctx.state.epochSeen.get(x)

  // ask yard-ctl for a JWT for the subject (no attempt of its own in flight;
  // at most one request a tick, a model bound)
  pure def listen_fetch(ctx: LocalContext): Set[Sbx] =
    if (ctx.state.nReq >= MAX_JWT_REQS or ctx.state.lastReqAt >= ctx.extensions.now) Set()
    else metaGets(ctx).map(g => subjectOf(RULES, g.tap, g.claimed))
      .filter(x => not(ctx.state.pend.exists(a => a.jwt.sbx == x)))

  pure def act_fetch(ctx: LocalContext, x: Sbx): Transition =
    { post_state: { ...ctx.state, nReq: ctx.state.nReq + 1, lastReqAt: ctx.extensions.now },
      effects: Set(send(CTL, JwtReq({ sbx: x, n: ctx.state.nReq, ip: ctx.state.ipSeen }))) }

  // a JWT arrived: exchange it once (never re-sent under the design)
  pure def listen_jwt(ctx: LocalContext): Set[Jwt] =
    ctx.messages.filterMap(m => match m { | JwtMsg(j) => Some(j) | _ => None })
      .filter(j => ctx.state.synced and not(ctx.state.usedJwt.contains(j.id)))

  // a JWT of a stale credential epoch is refused (SR0); a newer one teaches
  // the broker the new epoch
  pure def act_exchange(ctx: LocalContext, j: Jwt): Transition = {
    val st = ctx.state
    val fresh = currentEpoch(ctx, j.sbx, j.epoch)
    val live = ctx.extensions.now <= j.exp and fresh
    val a = { att: st.nAtt, jwt: j }
    val leak = if (RULES.forwardJwt) Set(send(j.sbx, CredResp({ secret: JwtTok(j.id) })),
                                         ghost(Reveal({ sbx: j.sbx, secret: JwtTok(j.id) }))) else Set()
    { post_state: { ...st, usedJwt: st.usedJwt.setAdd(j.id),
                    pend: if (live) st.pend.setAdd(a) else st.pend,
                    nAtt: if (live) st.nAtt + 1 else st.nAtt,
                    staleRefused: if (fresh) st.staleRefused else st.staleRefused + 1,
                    staleExchanged: if (live and j.epoch < st.epochSeen.get(j.sbx)) st.staleExchanged + 1 else st.staleExchanged,
                    epochSeen: st.epochSeen.set(j.sbx, max(st.epochSeen.get(j.sbx), j.epoch)) },
      effects: (if (live) Set(send(CLOUD, AssumeRole(a))) else Set()).union(leak) }
  }

  // an answer with credentials: hold it (a late one for a dropped attempt
  // is adopted too) unless it has expired, its grant was revoked, or its
  // epoch is stale; either way write the warden.mint row
  pure def listen_creds(ctx: LocalContext): Set[{ att: int, cred: Cred }] =
    ctx.messages.filterMap(m => match m { | CredsMsg(c) => Some(c) | _ => None })
      .filter(c => not(ctx.state.answered.contains(c.att)))

  pure def act_creds(ctx: LocalContext, c: { att: int, cred: Cred }): Transition = {
    val st = ctx.state
    val keep = and { st.synced, c.cred.exp > ctx.extensions.now, not(st.revoked.contains(c.cred.h)),
                     currentEpoch(ctx, c.cred.sbx, c.cred.epoch), c.cred.ip == st.ipSeen }
    { post_state: { ...st, answered: st.answered.setAdd(c.att),
                    pend: st.pend.filter(a => a.att != c.att),
                    held: if (keep) st.held.setAdd(c.cred) else st.held },
      effects: Set(send(CTL, MintAudit({ id: c.cred.id }))) }
  }

  // an error answer: the attempt is over for the design (an error after the
  // write is possible, so it is not taken as "not done": nothing is re-sent);
  // the blind-retry mutant re-sends the same JWT while it is valid
  pure def listen_err(ctx: LocalContext): Set[int] =
    ctx.messages.filterMap(m => match m { | MintErr(e) => Some(e.att) | MintRejected(e) => Some(e.att) | _ => None })
      .filter(i => ctx.state.pend.exists(a => a.att == i))

  pure def resendOrDrop(ctx: LocalContext, a: Attempt): LocalState = {
    val st = ctx.state
    val rest = st.pend.filter(p => p.att != a.att)
    if (RULES.retry == BlindRetry and ctx.extensions.now <= a.jwt.exp)
      { ...st, pend: rest.setAdd({ att: st.nAtt, jwt: a.jwt }), nAtt: st.nAtt + 1, timedOut: st.timedOut.setAdd(a.att) }
    else { ...st, pend: rest, timedOut: st.timedOut.setAdd(a.att) }
  }
  pure def resendFx(ctx: LocalContext, a: Attempt): Set[choreo::Effect[Node, Msg, (), Ghost]] =
    if (RULES.retry == BlindRetry and ctx.extensions.now <= a.jwt.exp)
      Set(send(CLOUD, AssumeRole({ att: ctx.state.nAtt, jwt: a.jwt }))) else Set()

  pure def act_err(ctx: LocalContext, i: int): Transition = {
    val a = ctx.state.pend.filter(p => p.att == i).getOnlyElement()
    { post_state: resendOrDrop(ctx, a), effects: resendFx(ctx, a) }
  }

  // no answer: drop the attempt once it is settled (design), at any time
  // with a re-send (blind retry), or never (wait for an answer)
  pure def listen_timeout(ctx: LocalContext): Set[Attempt] =
    ctx.state.pend.filter(a => mayDrop(RULES, a, ctx.extensions.now))

  pure def act_timeout(ctx: LocalContext, a: Attempt): Transition =
    { post_state: resendOrDrop(ctx, a), effects: resendFx(ctx, a) }

  pure def listen_revoke(ctx: LocalContext): Set[Hash] =
    ctx.messages.filterMap(m => match m { | Revoke(r) => Some(r.h) | _ => None })
      .filter(h => not(ctx.state.revoked.contains(h)))

  pure def act_revoke(ctx: LocalContext, h: Hash): Transition =
    { post_state: { ...ctx.state, revoked: ctx.state.revoked.setAdd(h), held: ctx.state.held.filter(c => c.h != h) },
      effects: Set() }

  pure def listen_epoch(ctx: LocalContext): Set[{ sbx: Sbx, epoch: int }] =
    ctx.messages.filterMap(m => match m { | EpochNotice(e) => Some(e) | _ => None })
      .filter(e => e.epoch >= ctx.state.epochSeen.get(e.sbx))
  // apply the new epoch (drop older credentials) and acknowledge it; a
  // repeated notice is acknowledged again (the first answer may be lost)
  pure def act_epoch(ctx: LocalContext, e: { sbx: Sbx, epoch: int }): Transition = {
    val st = ctx.state
    { post_state: { ...st, epochSeen: st.epochSeen.set(e.sbx, e.epoch),
        held: if (RULES.epochCheck) st.held.filter(c => not(c.sbx == e.sbx and c.epoch < e.epoch)) else st.held },
      effects: Set(send(CTL, EpochAck(e))) }
  }

  // on start and on reconnect the broker pulls the current epochs, and
  // exchanges, holds and serves nothing until the answer to its latest pull
  pure def listen_need_pull(ctx: LocalContext): Set[int] =
    if (not(ctx.state.synced) and ctx.state.pulls < MAX_PULLS) Set(ctx.state.pulls) else Set()
  pure def act_need_pull(ctx: LocalContext, n: int): Transition =
    { post_state: { ...ctx.state, pulls: n + 1 }, effects: Set(send(CTL, EpochPull({ n: n }))) }
  pure def listen_epoch_state(ctx: LocalContext): Set[Sbx -> int] =
    ctx.messages.filterMap(m => match m { | EpochState(e) => Some(e) | _ => None })
      .filter(e => not(ctx.state.synced) and e.n == ctx.state.pulls - 1).map(e => e.epochs)
  pure def act_epoch_state(ctx: LocalContext, es: Sbx -> int): Transition = {
    val st = ctx.state
    val seen = SBXS.mapBy(x => max(st.epochSeen.get(x), es.get(x)))
    { post_state: { ...st, synced: true, epochSeen: seen,
        held: if (RULES.epochCheck) st.held.filter(c => c.epoch >= seen.get(c.sbx)) else st.held },
      effects: Set() }
  }

  // the home IP changed (WARDEN 2.3): drop the cache; the next mint is a new
  // slot key under the per-grant cap (decision 7, 2026-10-07)
  pure def listen_ip(ctx: LocalContext): Set[int] = if (ctx.extensions.ip > ctx.state.ipSeen) Set(ctx.extensions.ip) else Set()
  pure def act_ip(ctx: LocalContext, ip: int): Transition =
    { post_state: { ...ctx.state, ipSeen: ip, held: Set() }, effects: Set() }

  // a crash: volatile state (attempts, cache, known epochs) is gone; used
  // JWTs are never re-sent; the restarted broker pulls the epochs
  pure def listen_crash(ctx: LocalContext): Set[()] =
    if (ctx.state.restarts < MAX_RESTARTS and ctx.state.held.size() > 0) Set(()) else Set()
  pure def act_crash(ctx: LocalContext, u: ()): Transition =
    { post_state: { ...ctx.state, pend: Set(), held: Set(), served: Set(), restarts: ctx.state.restarts + 1,
                    epochSeen: SBXS.mapBy(_ => 0), synced: false },
      effects: Set() }

  pure def broker_listener(ctx: LocalContext): Set[Transition] = Set(
    choreo::cue(ctx, listen_epoch, act_epoch),
    choreo::cue(ctx, listen_need_pull, act_need_pull),
    choreo::cue(ctx, listen_epoch_state, act_epoch_state),
    choreo::cue(ctx, listen_ip, act_ip),
    choreo::cue(ctx, listen_servable, act_serve),
    choreo::cue(ctx, listen_fetch, act_fetch),
    choreo::cue(ctx, listen_jwt, act_exchange),
    choreo::cue(ctx, listen_creds, act_creds),
    choreo::cue(ctx, listen_err, act_err),
    choreo::cue(ctx, listen_timeout, act_timeout),
    choreo::cue(ctx, listen_revoke, act_revoke),
    choreo::cue(ctx, listen_crash, act_crash),
  ).flatten()

  // ================================================================ cloud STS
  pure def listen_assume(ctx: LocalContext): Set[Attempt] =
    ctx.messages.filterMap(m => match m { | AssumeRole(a) => Some(a) | _ => None })
      .filter(a => not(ctx.state.done.contains(a.att)))

  // a valid JWT mints, answered with credentials or with an error (applied
  // anyway); an expired one is refused (the fence on a late copy)
  pure def act_assume(ctx: LocalContext, a: Attempt): Set[Transition] = {
    val st = ctx.state
    val now = ctx.extensions.now
    if (now <= a.jwt.exp) {
      val c = mint(a.jwt, a.att, now)
      val post = { ...st, done: st.done.setAdd(a.att), minted: st.minted.setAdd(c) }
      val trail = ghost(Trail({ id: c.id, h: c.h, at: now }))
      Set({ post_state: post, effects: Set(send(BROKER, CredsMsg({ att: a.att, cred: c })), trail) },
          { post_state: post, effects: Set(send(BROKER, MintErr({ att: a.att })), trail) })
    } else
      Set({ post_state: { ...st, done: st.done.setAdd(a.att) }, effects: Set(send(BROKER, MintRejected({ att: a.att }))) })
  }

  pure def listen_deny(ctx: LocalContext): Set[{ h: Hash, cutoff: int }] =
    ctx.messages.filterMap(m => match m { | DenyBefore(d) => Some(d) | _ => None })

  pure def act_deny(ctx: LocalContext, d: { h: Hash, cutoff: int }): Transition = {
    val st = ctx.state
    val cut = if (st.deny.has(d.h)) max(st.deny.get(d.h), d.cutoff) else d.cutoff
    { post_state: { ...st, deny: st.deny.put(d.h, cut) }, effects: Set(send(CTL, DenyOk(d))) }
  }

  pure def listen_orphan_deny(ctx: LocalContext): Set[int] =
    ctx.messages.filterMap(m => match m { | OrphanDeny(o) => Some(o.id) | _ => None })
  pure def act_orphan_deny(ctx: LocalContext, i: int): Transition =
    { post_state: { ...ctx.state, orphanDeny: ctx.state.orphanDeny.setAdd(i) }, effects: Set(send(CTL, OrphanDenyOk({ id: i }))) }

  pure def cloud_listener(ctx: LocalContext): Set[Transition] = Set(
    listen_assume(ctx).map(a => act_assume(ctx, a)).flatten(),
    choreo::cue(ctx, listen_deny, act_deny),
    choreo::cue(ctx, listen_orphan_deny, act_orphan_deny),
  ).flatten()

  // ================================================================ wiring
  pure def main_listener(ctx: LocalContext): Set[Transition] = {
    val p = ctx.state.process_id
    if (p.in(SBXS)) sbx_listener(ctx)
    else if (p == CTL) ctl_listener(ctx)
    else if (p == USER) user_listener(ctx)
    else if (p == BROKER) broker_listener(ctx)
    else cloud_listener(ctx)
  }

  def apply_custom_effect(env: GlobalContext, g: Ghost): GlobalContext = {
    val x = env.extensions
    val x1 = match g {
      | Shown(e) => { ...x, shown: x.shown.setAdd(e) }
      | Granted(e) => { ...x, seq: x.seq + 1, granted: x.granted.setAdd({ ...e, seq: x.seq }) }
      | Dead(c) => { ...x, seq: x.seq + 1, dead: x.dead.setAdd({ c: c, seq: x.seq }) }
      | Trail(e) => { ...x, trail: x.trail.setAdd(e) }
      | UserApproved(e) => { ...x, userApproved: x.userApproved.setAdd(e) }
      | UserTemplate(e) => { ...x, userTemplate: x.userTemplate.setAdd(e) }
      | Asserted(a) => { ...x, assertions: x.assertions.setAdd(a) }
      | Reveal(e) => { ...x, revealed: x.revealed.setAdd(e) }
    }
    { ...env, extensions: x1 }
  }

  pure def initialState(n: Node): LocalState = {
    process_id: n, sent: 0, cards: Map(), grants: Map(), handled: Set(), issued: Set(), jwtN: 0, templateOk: Set(),
    denyOk: Set(), refused: Set(), chIssued: Set(), chUsed: Set(), epoch: SBXS.mapBy(_ => 0),
    audited: Set(), orphans: Set(), orphanDenyOk: Set(), sess: SBXS.mapBy(_ => SActive), decided: Set(), asked: Set(), approved: Set(), aborted: Set(),
    pend: Set(), held: Set(), served: Set(), usedJwt: Set(), answered: Set(), timedOut: Set(),
    revoked: Set(), nReq: 0, lastReqAt: -1, nAtt: 0, restarts: 0, epochSeen: SBXS.mapBy(_ => 0), ipSeen: 0, staleRefused: 0, staleExchanged: 0, synced: true, pulls: 0, minted: Set(), done: Set(), deny: Map(), orphanDeny: Set(),
  }

  action init = choreo::init({
    system: NODES.mapBy(n => initialState(n)),
    messages: NODES.mapBy(n => if (n == BROKER) tuples(SBXS, SBXS).map(((t, c)) => MetaGet({ tap: t, claimed: c })) else Set()),
    events: NODES.mapBy(_ => Set()),
    extensions: { now: 0, seq: 0, shown: Set(), granted: Set(), dead: Set(), trail: Set(), ip: 0, userApproved: Set(),
                  userTemplate: Set(), assertions: Set(), revealed: Set() },
  })

  // time passes
  action tick = all {
    choreo::s.extensions.now < MAX_TIME,
    choreo::s' = { ...choreo::s, extensions: { ...choreo::s.extensions, now: choreo::s.extensions.now + 1 } },
  }

  // the network loses one message (a lost request or a lost answer); the
  // SDK's metadata polls repeat, so losing one is not modelled
  action loseMessage = {
    nondet v = NODES.oneOf()
    nondet m = choreo::s.messages.get(v).filter(m => match m { | MetaGet(_) => false | _ => true }).oneOf()
    choreo::s' = { ...choreo::s, messages: choreo::s.messages.setBy(v, b => b.exclude(Set(m))) }
  }

  // the home IP changes (dynamic IPv4, decision 3)
  action ipChange = all {
    choreo::s.extensions.ip < MAX_IP_CHANGES,
    choreo::s' = { ...choreo::s, extensions: { ...choreo::s.extensions, ip: choreo::s.extensions.ip + 1 } },
  }

  action protocolStep = choreo::step(main_listener, apply_custom_effect)

  // protocol steps weighted 8:1:1 against time and loss
  action step = any {
    protocolStep, protocolStep, protocolStep, protocolStep,
    protocolStep, protocolStep, protocolStep, protocolStep,
    tick, loseMessage, ipChange,
  }

  // ================================================================ scripting API (for wardenTest.qnt)
  def with_cue(process, listen_fn, params) = choreo::with_cue(process, listen_fn, params)
  action perform(cue_ctx, upon_fn) = choreo::perform(cue_ctx, upon_fn, apply_custom_effect)
  // the one transition of process v that satisfies f
  action doWith(v: Node, f: Transition => bool): bool = choreo::step_with_filter(v, main_listener, apply_custom_effect, f)
  // the network loses message m on its way to v
  action loseMsg(v: Node, m: Msg): bool = all {
    choreo::s.messages.get(v).contains(m),
    choreo::s' = { ...choreo::s, messages: choreo::s.messages.setBy(v, b => b.exclude(Set(m))) },
  }

  // ================================================================ views for properties
  val s = choreo::s
  val now = s.extensions.now
  val ctlSt = s.system.get(CTL)
  val brokerSt = s.system.get(BROKER)
  val cloudSt = s.system.get(CLOUD)
  val minted = cloudSt.minted
  val ghostX = s.extensions
  val brokerCtx = choreo::convert_context(s, BROKER)

  def firstGrant(h: Hash): Set[GrantLog] = {
    val gs = ghostX.granted.filter(g => g.h == h)
    gs.filter(g => gs.forall(o => g.seq <= o.seq))
  }
  // the TTL the user approved for h (the requested one when no user approved it)
  def approvedTtl(h: Hash): int = {
    val us = ghostX.userApproved.filter(u => u.h == h)
    if (us.size() == 0) h.of.ttl else us.fold(h.of.ttl, (acc, u) => min(acc, u.ttl))
  }

  // ================================================================ invariants
  // P1a: every credential minted carries a session policy whose hash the user
  // approved, for the principal its JWT names
  val mintedMatchesApproval: bool = minted.forall(c => and {
    ghostX.userApproved.exists(u => u.h == hash(c.policy)),
    c.h == hash(c.policy),
    c.sbx == c.policy.sbx,
  })

  // P1b: no credential outlives the approved TTL, counted from the first grant
  val credWithinApprovedTtl: bool = minted.forall(c =>
    firstGrant(c.h).forall(g => c.issuedAt >= g.at and c.exp <= g.at + approvedTtl(c.h)))

  // P2: no mint without a user approval event (exact card or, where the design
  // has it, the session-template button); a draft never counts
  val noMintWithoutUserApproval: bool = minted.forall(c => or {
    ghostX.userApproved.exists(u => u.h == hash(c.policy) and u.at <= c.issuedAt),
    ghostX.userTemplate.contains({ sbx: c.policy.sbx, pol: c.policy.pol }),
  })

  // P3: an escalation is minted only under a grant whose approval carried a
  // passkey assertion the user made, bound to that card's hash and fresh
  // when the warden accepted it
  val escalationHasFreshPasskey: bool = minted.filter(c => isEsc(c.policy)).forall(c =>
    ghostX.granted.exists(g => and {
      g.h == hash(c.policy),
      match g.asr {
        | Some(a) => and { a.h == g.h, g.at - a.chAt <= PASSKEY_FRESH, ghostX.assertions.contains(a),
                           ghostX.granted.forall(o => o.asr == Some(a) implies o.h == g.h) }
        | None => false
      },
    }))

  // P4a: one approval creates one grant (duplicates and replays change nothing)
  val oneGrantPerApproval: bool = ghostX.granted.forall(g1 => ghostX.granted.forall(g2 =>
    g1.h == g2.h implies g1.seq == g2.seq))

  // P4b: at most one credential per (grant, 10-min slot, home-IP
  // generation); renewal and IP-change re-mints are new keys (decision 7)
  val atMostOneMintPerSlot: bool = minted.forall(c1 => minted.forall(c2 =>
    (c1.h == c2.h and c1.slot == c2.slot and c1.ip == c2.ip) implies c1.id == c2.id))

  // P4c: ... and at most MAX_MINTS_PER_GRANT per grant in all
  val mintsPerGrantCapped: bool = minted.forall(c => minted.filter(o => o.h == c.h).size() <= MAX_MINTS_PER_GRANT)

  // P5a: a denied, withdrawn, superseded or expired card is never granted
  val deadCardsNotRedeemed: bool = ghostX.granted.forall(g => and {
    not(ghostX.dead.exists(d => d.c == cid(g.h.of) and d.seq < g.seq)),
    ghostX.shown.exists(sh => sh.c == cid(g.h.of) and g.at <= sh.at + CARD_EXP),
  })

  // P5c: a task has at most one live grant, and none once withdrawn
  // (decision 10: a newer approval or a withdraw revokes the old grant)
  val oneLiveGrantPerTask: bool = ctlSt.cards.keys().forall(k => {
    val live = ctlSt.grants.values().filter(g => g.key == k and g.revokedAt < 0)
    live.size() <= 1 and (ctlSt.cards.get(k).status == Withdrawn implies live.size() == 0)
  })

  // P5b: once the revoke deny has applied, no credential of that grant is usable
  val revokedCredsUnusable: bool = minted.forall(c =>
    (cloudSt.deny.has(c.h)) implies not(usable(c, cloudSt.deny, cloudSt.orphanDeny, now)))

  // P6 (as designed, IDENTITY.md): the sandbox never holds a federated credential (the STS JWT)
  val noFederatedCredInSandbox: bool = ghostX.revealed.forall(r => match r.secret {
    | JwtTok(_) => false
    | _ => true
  })

  // P6 (strict, as the brief states it): no cloud credential reaches the sandbox
  val noCloudCredInSandbox: bool = ghostX.revealed.forall(r => match r.secret {
    | CloudCred(_) => false
    | _ => true
  })

  // P7: a sandbox only ever receives what was minted for its own identity
  val sandboxOnlyOwnCreds: bool = ghostX.revealed.forall(r => match r.secret {
    | CloudCred(i) => minted.forall(c => c.id == i implies (c.sbx == r.sbx and c.policy.sbx == r.sbx))
    | Surrogate(i) => minted.forall(c => c.id == i implies (c.sbx == r.sbx and c.policy.sbx == r.sbx))
    | JwtTok(_) => true
  })

  // liveness as a state property: an attempt past its settle bound (the JWT
  // has expired, so no copy can still land) can be resolved now, so a lost
  // answer never leaves an approved grant stuck
  val settledAttemptResolvable: bool = {
    val ctx = brokerCtx
    brokerSt.pend.forall(a => now > a.jwt.exp implies or {
      listen_timeout(ctx).contains(a),
      listen_err(ctx).contains(a.att),
      listen_creds(ctx).exists(c => c.att == a.att),
    })
  }

  // P8 (SR0, branch sr0): the broker never exchanges a JWT of a stale
  // credential epoch and holds (so serves) only the current epoch it knows;
  // and once a session is Active again, the broker holds no credential of
  // an epoch older than the session's current one (resume waits for the
  // broker's acknowledgement). An exchange already in flight when the epoch
  // moves cannot be recalled: its answer is refused on arrival, and a mint
  // it made is an orphan that the reconciler records and revokes.
  val brokerHonoursCurrentEpoch: bool = and {
    brokerSt.staleExchanged == 0,
    brokerSt.held.forall(c => c.epoch >= brokerSt.epochSeen.get(c.sbx)),
    SBXS.forall(x => ctlSt.sess.get(x) == SActive implies
      brokerSt.held.forall(c => c.sbx == x implies c.epoch >= ctlSt.epoch.get(x))),
  }

  // L2 (decision 12): a mint nobody heard about (its answer lost or an error,
  // or the broker crashed) is found: once CloudTrail has it (CT_LAG), the
  // reconciler can record it now; and a recorded orphan whose revoke is not
  // yet confirmed can have it (re)sent now
  val orphansReconcilable: bool = {
    val ctx = choreo::convert_context(s, CTL)
    and {
      ghostX.trail.forall(e => (now >= e.at + CT_LAG and not(ctlSt.audited.contains(e.id)) and not(ctlSt.orphans.contains(e.id)))
        implies listen_reconcile(ctx).contains(e.id)),
      ctlSt.orphans.forall(i => not(ctlSt.orphanDenyOk.contains(i)) implies listen_orphan_unconfirmed(ctx).contains(i)),
    }
  }

  val safety: bool = and {
    mintedMatchesApproval, credWithinApprovedTtl, noMintWithoutUserApproval, escalationHasFreshPasskey,
    oneGrantPerApproval, atMostOneMintPerSlot, mintsPerGrantCapped, deadCardsNotRedeemed, oneLiveGrantPerTask,
    revokedCredsUnusable, noFederatedCredInSandbox, sandboxOnlyOwnCreds, brokerHonoursCurrentEpoch,
    settledAttemptResolvable, orphansReconcilable,
  }
  // the strict P6 on top (Azure surrogate mode only; AWS mode hands the VM credentials by decision 5)
  val safetyStrict: bool = and { safety, noCloudCredInSandbox }

  // ================================================================ witnesses (reachable targets)
  val wMinted: bool = minted.size() > 0
  val wServed: bool = ghostX.revealed.exists(r => match r.secret { | JwtTok(_) => false | _ => true })
  val wEscMinted: bool = minted.exists(c => isEsc(c.policy))
  val wShorterTtl: bool = minted.exists(c => ghostX.shown.exists(sh => sh.c == cid(c.policy)) and
    ctlSt.cards.values().exists(k => cid(k.content) == cid(c.policy) and k.content.ttl > c.policy.ttl))
  val wDenied: bool = ctlSt.cards.values().exists(c => c.status == Denied)
  val wWithdrawn: bool = ctlSt.cards.values().exists(c => c.status == Withdrawn)
  val wBlocked: bool = ctlSt.cards.values().exists(c => c.status == Blocked)
  val wExpiredRefused: bool = ctlSt.refused.contains("expired")
  val wStaleVersionRefused: bool = ctlSt.refused.contains("hash")
  val wPasskeyRefused: bool = ctlSt.refused.contains("passkey")
  val wOrphanMint: bool = minted.exists(c => brokerSt.timedOut.contains(c.id))
  val wLateAdopted: bool = brokerSt.held.exists(c => brokerSt.timedOut.contains(c.id))
  val wRemint: bool = minted.exists(c1 => minted.exists(c2 => c1.h == c2.h and c1.slot != c2.slot))
  val wRemintAfterLoss: bool = minted.exists(c1 => minted.exists(c2 =>
    c1.h == c2.h and c1.slot < c2.slot and not(brokerSt.answered.contains(c1.id))))
  val wRevokeApplied: bool = minted.exists(c => cloudSt.deny.has(c.h))
  val wRefusedExpiredJwt: bool = cloudSt.done.exists(i => not(minted.exists(c => c.id == i)))
  val wBrokerCrash: bool = brokerSt.restarts > 0 and minted.size() > 0
  val wReconciled: bool = ctlSt.orphans.size() > 0
  val wOrphanRevoked: bool = cloudSt.orphanDeny.size() > 0
  val wResumed: bool = SBXS.exists(x => ctlSt.epoch.get(x) > 0 and ctlSt.sess.get(x) == SActive)
  val wBrokerResynced: bool = brokerSt.restarts > 0 and brokerSt.synced
  val wStaleEpochRefused: bool = brokerSt.staleRefused > 0
  val wIpRemint: bool = minted.exists(c1 => minted.exists(c2 => c1.h == c2.h and c1.ip != c2.ip))
  val wSupersededRevoked: bool = ctlSt.grants.values().exists(g1 => ctlSt.grants.values().exists(g2 =>
    g1.key == g2.key and g1.h != g2.h and g1.revokedAt >= 0))
  val wWithdrawRevoked: bool = ctlSt.cards.keys().exists(k => ctlSt.cards.get(k).status == Withdrawn and
    ctlSt.grants.values().exists(g => g.key == k and g.revokedAt >= 0))
}
