// Slashing safety of the signing protocol: 4 nodes, f = 1, a signature needs 3 partials.
// See docs/formal.md. The replicated rules (`decide`) are the specification the Kani proofs
// (formal/kani) show `src/slashing.rs` implements; this model checks what the network does with
// them: consensus, the atomic record and authorization, the keyholders' signing gate, crashes,
// rollbacks of one node or of every node, the restart floor and the WORM anchor.
//
// Abstractions:
// - Consensus is a single finalized log of duty commands (BFT safety is assumed, not modeled).
//   `authAt[k]` is the authorized set after the first k commands. A node's durable state is a
//   prefix of the log (`height`): the record and the authorization are one commit.
// - One validator key. A duty is a block (slot) or an attestation (source, target); `data`
//   stands for the rest of the signed object. Clients are arbitrary: any duty can be decided.
// - Time: each node's clock counts slots (an epoch per slot), never runs backwards on that node,
//   and nodes may disagree. A keyholder signs a block or attestation only once its slot (target)
//   has started by its clock (the time horizon).
// - The Byzantine nodes sign everything: they always count toward a quorum.
// - The anchor's records are the marks an honest keyholder wrote before each partial. At start a
//   node takes, for each mark, the second-highest value across nodes; the Byzantine record is
//   chosen at each read, as low or as high as it can be.
module slashing {
  const BYZANTINE: Set[str]
  const WHOLE_ROLLBACK: bool
  const RESTART_FLOOR: bool
  const ANCHOR: bool
  // The restart floor exempts the duties a keyholder loaded at start (the code before the fix of
  // BUG-10). The anchored marks always do (`KnownDuty::loaded` in `dkg::actor`).
  const FLOOR_EXEMPTS_LOADED: bool
  const MAX_LOG: int

  pure val NODES = Set("n1", "n2", "n3", "n4")
  pure val QUORUM = 3
  pure val NONE = -1

  type Duty = { block: bool, slot: int, source: int, target: int, data: int }
  type Marks = { slot: int, source: int, target: int }

  pure val NO_MARKS: Marks = { slot: NONE, source: NONE, target: NONE }

  val HONEST = NODES.exclude(BYZANTINE)

  pure def block(slot: int, data: int): Duty =
    { block: true, slot: slot, source: NONE, target: NONE, data: data }
  pure def attestation(source: int, target: int, data: int): Duty =
    { block: false, slot: NONE, source: source, target: target, data: data }

  // The duties clients may send (a small scope, chosen so that every kind of conflict occurs):
  // two blocks of slot 1, two attestations of target 1 (a double vote), and an attestation
  // (1, 1) that (0, 2) surrounds. Every slot and epoch is at most MAX_TIME.
  pure val MAX_TIME = 2
  pure val DUTIES: Set[Duty] = Set(
    block(1, 0), block(1, 1),
    attestation(0, 1, 0), attestation(0, 1, 1),
    attestation(1, 1, 0), attestation(0, 2, 0),
  )

  // The slot a duty belongs to: a block's slot, an attestation's target.
  pure def time(d: Duty): int = if (d.block) d.slot else d.target

  // Proposer slashing and the double vote: two different duties of one slot or target.
  pure def double(a: Duty, b: Duty): bool =
    a.block == b.block and a != b and time(a) == time(b)

  // `is_slashable_attestation_data`'s surround vote, in either order.
  pure def surround(a: Duty, b: Duty): bool =
    not(a.block) and not(b.block) and (
      (a.source < b.source and b.target < a.target) or
      (b.source < a.source and a.target < b.target)
    )

  pure def slashable(a: Duty, b: Duty): bool = double(a, b) or surround(a, b)

  // The replicated rules: an exact repeat stays authorized, a slashable duty is refused, any
  // other is authorized (Kani K-1 and K-2 show the code decides exactly this).
  pure def decide(auth: Set[Duty], d: Duty): Set[Duty] =
    if (auth.contains(d) or auth.exists(a => slashable(a, d))) auth else auth.union(Set(d))

  pure def raise(m: Marks, d: Duty): Marks =
    if (d.block) { ...m, slot: if (d.slot > m.slot) d.slot else m.slot }
    else {
      ...m,
      source: if (d.source > m.source) d.source else m.source,
      target: if (d.target > m.target) d.target else m.target,
    }

  // The second-highest of the values of `v` (with repetitions).
  pure def secondHighest(v: str -> int): int =
    v.keys().fold(NONE, (acc, i) =>
      if (v.keys().exists(j => j != i and v.get(j) >= v.get(i)) and v.get(i) > acc) v.get(i)
      else acc)

  var authAt: List[Set[Duty]]
  var height: str -> int
  var clock: str -> int
  // The restart floor: the slot started when the keyholder's process started.
  var floor: str -> int
  // The authorizations a keyholder loaded at start.
  var loaded: str -> Set[Duty]
  // Each honest keyholder's latest anchor record: its marks, and the block it names (its height
  // and the state that block left, which stands for the block's digest).
  var records: str -> Marks
  var recordHeight: str -> int
  var recordState: str -> Set[Duty]
  var anchored: str -> Marks
  // Stopped with exit status 77: the anchor shows a rollback.
  var halted: str -> bool
  var partials: Set[(str, Duty)]

  def authOf(i: str): Set[Duty] = authAt[height.get(i)]

  def signers(d: Duty): int =
    HONEST.filter(i => partials.contains((i, d))).size() + BYZANTINE.size()

  def signed(d: Duty): bool = signers(d) >= QUORUM

  // What a node reads from the anchor at start, the Byzantine record as `byzantine`.
  def anchorRead(byzantine: Marks): Marks = {
    val recs = NODES.mapBy(i => if (BYZANTINE.contains(i)) byzantine else records.get(i))
    {
      slot: secondHighest(recs.keys().mapBy(i => recs.get(i).slot)),
      source: secondHighest(recs.keys().mapBy(i => recs.get(i).source)),
      target: secondHighest(recs.keys().mapBy(i => recs.get(i).target)),
    }
  }

  // Rules (a) and (b) of docs/anchor.md: the records of two or more nodes name other blocks at
  // heights a node at height `h` of `log` has applied. Only honest records are counted: the
  // Byzantine one can add a stop, never prevent one. The confirmation gate is not modeled: it only
  // refuses more.
  def rolledBack(log: List[Set[Duty]], h: int): bool =
    ANCHOR and HONEST.filter(j =>
      recordHeight.get(j) > 0 and recordHeight.get(j) <= h and
      log[recordHeight.get(j)] != recordState.get(j)
    ).size() >= 2

  def floorAllows(i: str, d: Duty): bool =
    not(RESTART_FLOOR) or (FLOOR_EXEMPTS_LOADED and loaded.get(i).contains(d)) or
      time(d) > floor.get(i)

  def anchorAllows(i: str, d: Duty): bool = {
    val m = anchored.get(i)
    not(ANCHOR) or loaded.get(i).contains(d) or (
      if (d.block) d.slot > m.slot
      else d.target > m.target and d.source >= m.source
    )
  }

  action init = all {
    authAt' = [Set()],
    height' = NODES.mapBy(_ => 0),
    clock' = NODES.mapBy(_ => 0),
    floor' = NODES.mapBy(_ => NONE),
    loaded' = NODES.mapBy(_ => Set()),
    records' = NODES.mapBy(_ => NO_MARKS),
    recordHeight' = NODES.mapBy(_ => 0),
    recordState' = NODES.mapBy(_ => Set()),
    anchored' = NODES.mapBy(_ => NO_MARKS),
    halted' = NODES.mapBy(_ => false),
    partials' = Set(),
  }

  // Consensus decides a duty command; every node decides it with the same rules.
  action decideDuty(d: Duty): bool = all {
    authAt.length() <= MAX_LOG,
    authAt' = authAt.append(decide(authAt[authAt.length() - 1], d)),
    height' = height, clock' = clock, floor' = floor, loaded' = loaded, records' = records,
    recordHeight' = recordHeight, recordState' = recordState, anchored' = anchored,
    halted' = halted, partials' = partials,
  }

  // A node applies the next finalized block: records and authorizations in one sync.
  action apply(i: str): bool = all {
    height.get(i) < authAt.length() - 1,
    height' = height.set(i, height.get(i) + 1),
    halted' = halted.set(i, halted.get(i) or rolledBack(authAt, height.get(i) + 1)),
    authAt' = authAt, clock' = clock, floor' = floor, loaded' = loaded, records' = records,
    recordHeight' = recordHeight, recordState' = recordState, anchored' = anchored,
    partials' = partials,
  }

  action tick(i: str): bool = all {
    clock.get(i) < MAX_TIME,
    clock' = clock.set(i, clock.get(i) + 1),
    authAt' = authAt, height' = height, floor' = floor, loaded' = loaded, records' = records,
    recordHeight' = recordHeight, recordState' = recordState, anchored' = anchored,
    halted' = halted, partials' = partials,
  }

  // An honest keyholder gives a partial only for a duty its committed state authorizes, whose
  // slot has started, past its restart floor and anchored marks; it writes its anchor record
  // first.
  action sign(i: str, d: Duty): bool = all {
    not(halted.get(i)),
    authOf(i).contains(d),
    time(d) <= clock.get(i),
    floorAllows(i, d),
    anchorAllows(i, d),
    partials' = partials.union(Set((i, d))),
    records' = if (ANCHOR) records.set(i, raise(records.get(i), d)) else records,
    recordHeight' = if (ANCHOR) recordHeight.set(i, height.get(i)) else recordHeight,
    recordState' = if (ANCHOR) recordState.set(i, authOf(i)) else recordState,
    authAt' = authAt, height' = height, clock' = clock, floor' = floor, loaded' = loaded,
    anchored' = anchored, halted' = halted,
  }

  // A crash and restart, or a restore of the node from older storage (a prefix: `h`). Its peers
  // keep the log, which it replays.
  action restart(i: str, h: int, byzantine: Marks): bool = all {
    h <= height.get(i),
    height' = height.set(i, h),
    floor' = if (RESTART_FLOOR) floor.set(i, clock.get(i)) else floor,
    loaded' = loaded.set(i, authAt[h]),
    anchored' = if (ANCHOR) anchored.set(i, anchorRead(byzantine)) else anchored,
    halted' = halted.set(i, halted.get(i) or rolledBack(authAt, h)),
    authAt' = authAt, clock' = clock, records' = records, recordHeight' = recordHeight,
    recordState' = recordState, partials' = partials,
  }

  // L-1: every node's storage restored to before command `k`, and every node restarted. The log
  // after it is lost with them; the anchor's records are outside the rollback domain.
  action rollbackAll(k: int, byzantine: Marks): bool = all {
    WHOLE_ROLLBACK,
    k < authAt.length() - 1,
    val log = authAt.slice(0, k + 1)
    val h = NODES.mapBy(i => if (height.get(i) < k) height.get(i) else k)
    all {
      authAt' = log,
      height' = h,
      floor' = if (RESTART_FLOOR) clock else floor,
      loaded' = NODES.mapBy(i => log[h.get(i)]),
      anchored' = if (ANCHOR) NODES.mapBy(_ => anchorRead(byzantine)) else anchored,
      halted' = NODES.mapBy(i => halted.get(i) or rolledBack(log, h.get(i))),
    },
    clock' = clock, records' = records, recordHeight' = recordHeight,
    recordState' = recordState, partials' = partials,
  }

  action step = {
    nondet d = DUTIES.oneOf()
    nondet i = HONEST.oneOf()
    nondet k = 0.to(MAX_LOG).oneOf()
    nondet low = Set(true, false).oneOf()
    val byzantine = if (low or not(ANCHOR)) NO_MARKS
      else { slot: MAX_TIME, source: MAX_TIME, target: MAX_TIME }
    any {
      decideDuty(d),
      apply(i),
      tick(i),
      sign(i, d),
      restart(i, k, byzantine),
      rollbackAll(k, byzantine),
    }
  }

  // No two slashable duties both have a quorum of partials.
  val noDoubleSignature = DUTIES.forall(a => DUTIES.forall(b =>
    double(a, b) implies not(signed(a) and signed(b))))
  val noSurroundSignature = DUTIES.forall(a => DUTIES.forall(b =>
    surround(a, b) implies not(signed(a) and signed(b))))
  val safety = noDoubleSignature and noSurroundSignature
}

// Every configuration but `rollbackFloorExempt` is the code as it is. Removing an exemption only
// removes steps, so a property TLC proves with FLOOR_EXEMPTS_LOADED holds without it too.

// The fault model: one Byzantine node, crashes and one-node restores, no whole rollback.
module faultModel {
  import slashing(
    BYZANTINE = Set("n4"), WHOLE_ROLLBACK = false, RESTART_FLOOR = true, ANCHOR = false,
    FLOOR_EXEMPTS_LOADED = false, MAX_LOG = 2,
  ).*
}

// L-1 without the restart floor: a double proposal is signed (the E2E reproducer).
module rollbackNoFloor {
  import slashing(
    BYZANTINE = Set("n4"), WHOLE_ROLLBACK = true, RESTART_FLOOR = false, ANCHOR = false,
    FLOOR_EXEMPTS_LOADED = false, MAX_LOG = 2,
  ).*

  pure val b1 = block(1, 0)
  pure val b1other = block(1, 1)

  run doubleProposalTest =
    init.then(tick("n1")).then(tick("n2"))
      .then(decideDuty(b1)).then(apply("n1")).then(apply("n2"))
      .then(sign("n1", b1)).then(sign("n2", b1))
      .then(rollbackAll(0, NO_MARKS))
      .then(decideDuty(b1other)).then(apply("n1")).then(apply("n2"))
      .then(sign("n1", b1other)).then(sign("n2", b1other))
      .expect(not(noDoubleSignature))
}

// BUG-10, the code before its fix: the floor refuses the other block at first, but the next
// restart loads it as an authorized duty, exempt from the floor, and signs it.
module rollbackFloorExempt {
  import slashing(
    BYZANTINE = Set("n4"), WHOLE_ROLLBACK = true, RESTART_FLOOR = true, ANCHOR = false,
    FLOOR_EXEMPTS_LOADED = true, MAX_LOG = 2,
  ).*

  pure val b1 = block(1, 0)
  pure val b1other = block(1, 1)

  run restartAfterRollbackSignsADoubleProposalTest =
    init.then(tick("n1")).then(tick("n2"))
      .then(decideDuty(b1)).then(apply("n1")).then(apply("n2"))
      .then(sign("n1", b1)).then(sign("n2", b1))
      .then(rollbackAll(0, NO_MARKS))
      .then(decideDuty(b1other)).then(apply("n1")).then(apply("n2"))
      // The floor refuses it.
      .expect(not(floorAllows("n1", b1other)) and not(floorAllows("n2", b1other)))
      // A plain restart of each node, on the state it has.
      .then(restart("n1", 1, NO_MARKS)).then(restart("n2", 1, NO_MARKS))
      .then(sign("n1", b1other)).then(sign("n2", b1other))
      .expect(not(noDoubleSignature))
}

// L-1 with the restart floor: no double proposal or vote; a crafted surround vote is signed.
module rollbackFloor {
  import slashing(
    BYZANTINE = Set("n4"), WHOLE_ROLLBACK = true, RESTART_FLOOR = true, ANCHOR = false,
    FLOOR_EXEMPTS_LOADED = false, MAX_LOG = 2,
  ).*

  pure val b1 = block(1, 0)
  pure val b1other = block(1, 1)
  pure val inner = attestation(1, 1, 0)
  pure val outer = attestation(0, 2, 0)

  // BUG-10's scenario: the floor of the next restart still refuses.
  run restartAfterRollbackStillRefusesTest =
    init.then(tick("n1")).then(tick("n2"))
      .then(decideDuty(b1)).then(apply("n1")).then(apply("n2"))
      .then(sign("n1", b1)).then(sign("n2", b1))
      .then(rollbackAll(0, NO_MARKS))
      .then(decideDuty(b1other)).then(apply("n1")).then(apply("n2"))
      .then(restart("n1", 1, NO_MARKS)).then(restart("n2", 1, NO_MARKS))
      .expect(not(floorAllows("n1", b1other)) and not(floorAllows("n2", b1other)))

  run surroundVoteTest =
    init.then(tick("n1")).then(tick("n2"))
      .then(decideDuty(inner)).then(apply("n1")).then(apply("n2"))
      .then(sign("n1", inner)).then(sign("n2", inner))
      .then(rollbackAll(0, NO_MARKS))
      .then(tick("n1")).then(tick("n2"))
      .then(decideDuty(outer)).then(apply("n1")).then(apply("n2"))
      .then(sign("n1", outer)).then(sign("n2", outer))
      .expect(not(noSurroundSignature))
}

// L-1 with the restart floor and the WORM anchor: no slashable pair.
module rollbackAnchor {
  import slashing(
    BYZANTINE = Set("n4"), WHOLE_ROLLBACK = true, RESTART_FLOOR = true, ANCHOR = true,
    FLOOR_EXEMPTS_LOADED = false, MAX_LOG = 2,
  ).*

  pure val b1 = block(1, 0)
  pure val b1other = block(1, 1)

  // BUG-10's scenario under the floor's exemption would be stopped here too: the nodes stop when
  // they apply the other block, whose height the records name with another digest (rule (b)).
  run rollbackIsDetectedTest =
    init.then(tick("n1")).then(tick("n2"))
      .then(decideDuty(b1)).then(apply("n1")).then(apply("n2"))
      .then(sign("n1", b1)).then(sign("n2", b1))
      .then(rollbackAll(0, NO_MARKS))
      .then(decideDuty(b1other)).then(apply("n1")).then(apply("n2"))
      .expect(halted.get("n1") and halted.get("n2"))
}
