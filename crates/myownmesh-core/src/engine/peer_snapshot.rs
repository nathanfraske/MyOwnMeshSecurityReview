//! The funded peers snapshot: what publishing every peer costs, counted before
//! anything is built.
//!
//! `NetworkState::peer_snapshot` — reached publicly as
//! [`JoinedNetwork::peers`](crate::JoinedNetwork::peers) — answers the same
//! question by allocating first and asking later. It is the
//! right shape for a library caller that owns the process. It is the wrong
//! shape for a daemon serving a control request on behalf of somebody else,
//! because the size of its answer is a function of how many peers exist and how
//! large an advertisement each of them chose to send — neither of which the
//! daemon picked.
//!
//! # The five acquisitions
//!
//! Every one of them is separately refusable, because they fail for different
//! reasons and a caller that could only refuse the total would have to refuse a
//! cheap roster because one peer advertised a large blob.
//!
//! 1. **Membership staging** — the slices naming which peers this snapshot is
//!    about. Funded before the count is turned into an allocation, which is why
//!    [`PeerSnapshotStaging`] exists as a step of its own rather than being
//!    folded into `prepare`.
//! 2. **Work** — the passes made over peer-controlled bytes: two validating
//!    each advertisement copy, and two more for the line seam's count and
//!    encode. Transient: the lease is released inside
//!    [`PreparedPeerSnapshot::commit`] once those walks are done, because
//!    nothing retains the work.
//! 3. **Typed retention** — the published rows and the owned strings in them.
//!    Bounded by the roster, not by the peers.
//! 4. **Output retention** — the advertisement bytes themselves. Peer-chosen
//!    size, and one of two unbounded terms here, which is exactly why it is not
//!    mixed into the typed claim.
//! 5. **Line** — the buffer the published bytes occupy, admitted at the ceiling
//!    [`PreparedPeerSnapshot::encoded_line_ceiling`] quotes and then narrowed to
//!    the width that was actually counted. Separate from output retention
//!    because it is a different quantity: what a row *holds* and what a row
//!    *encodes to* are two measurements, and only the second one sizes the
//!    write.
//!
//! Only the fifth outlives `commit`. Claims 1 through 4 fund things that exist
//! while the answer is being built — the staged membership, the walks, the rows
//! and their advertisements — and every one of them is released inside `commit`
//! as the thing it funded dies. What a [`FundedPeerSnapshot`] holds is the
//! encoded line and one lease sized for exactly that.
//!
//! # Why every retained thing is a boxed slice
//!
//! `Vec::with_capacity` and `String::with_capacity` promise *at least* the
//! requested capacity, and `clone`, `to_owned` and `collect` promise no more
//! than that either. A claim resting on any of them would be a lower bound
//! presented as an exact figure. `Box<[T]>` and `Box<str>` have no capacity at
//! all — their allocation is laid out for their length and freed against that
//! same layout — so every retained field here is one, and every `Vec` that
//! appears is transient scaffolding shrunk on the way out.
//!
//! # The line gate
//!
//! Retention and encoded width are independent. Two rows can retain identical
//! bytes and serialize to different lengths — a label whose characters need
//! escaping, a number that grew a digit — so a snapshot funded only for what it
//! holds could still overrun the buffer it is written into.
//!
//! Pass A quotes a ceiling by arithmetic over the measured lengths, allocating
//! nothing. The caller funds a line lease for that ceiling. `commit` then counts
//! what the built rows *actually* encode to, without allocating, refuses if that
//! exceeds the ceiling, and otherwise narrows the lease to the counted width
//! before producing the bytes. Nothing is published on the strength of the
//! prediction; the prediction only decides what may be attempted, and the
//! reservation that survives is for what was written rather than for what was
//! allowed.
//!
//! # What is still not exact
//!
//! Every retained value here is a boxed slice or a `Box<str>`, so every
//! *retention* charge is exact — a boxed slice's layout is its length. But each
//! of those is built through a `Vec`, and `Vec::with_capacity` promises only
//! *at least* the requested capacity. So for the moment between allocating the
//! builder and shrinking it, the **peak** is a bound rather than a figure, and
//! nothing charges for the difference.
//!
//! There are four such paths, and they are listed rather than summarised
//! because a reader checking this claim has to be able to find all of them:
//!
//! 1. **The staged measurements** — `lengths: Box<[PeerRowLengths]>` in
//!    [`PeerSnapshotStaging::stage`], built by `collect()`. Collecting into a
//!    `Box<[T]>` is not a distinct allocation strategy: `FromIterator` fills a
//!    `Vec` and calls `into_boxed_slice`, so this has the same peak as an
//!    explicit `with_capacity` even though no `with_capacity` appears.
//! 2. **The row builder** — the `Vec<PublishedPeer>` in
//!    [`PreparedPeerSnapshot::commit`], shrunk before the rows are counted.
//! 3. **The encode buffer** — the `Vec<u8>` in `encode_line_exact`, reserved at
//!    the already-counted width and handed out as a boxed slice.
//! 4. **The staged membership** — `PeerRegistry::stage_owners`, which is outside
//!    this module and carries the same caveat at its own definition. It is named
//!    here anyway, because the membership claim quoted by
//!    [`PeerSnapshotStaging::membership_claim`] is what funds it, and a reader
//!    auditing that claim should not have to already know where the allocation
//!    lives.
//!
//! Removing the gap needs an exactly-sized uninitialized allocation, which on
//! stable Rust means `unsafe`. This crate has none, and adding the first is not
//! a decision this module should take on its own — the ruling on record is to
//! keep the safe shape and state the bound here instead. The same pattern is
//! what `crate::protocol`'s `encode_json_exact` uses, and that path funds every
//! retained capability advertisement, so it is a question the whole crate
//! answers together or not at all.
//!
//! # The two passes
//!
//! Pass A measures. It observes each peer once through
//! `PeerConnection::with_peer_view`
//! — one observation covering both the peer's state and its promoted session,
//! so an advertisement can never be paired with state read at a different
//! moment — and records what publishing that peer would cost. It builds nothing
//! and allocates nothing beyond the staged slices it was already funded for.
//!
//! Pass B builds, under the leases pass A's numbers were funded with. For each
//! staged peer it re-settles two separate questions before constructing
//! anything:
//!
//! * **Identity** — is the staged owner token still the installed peer? A
//!   replacement is a different peer that happens to reuse a device id, and
//!   `PeerRegistry::get_if_current`
//!   is what distinguishes them. Length equality alone would not: a replacement
//!   whose label and advertisement happen to be the same size passes every
//!   arithmetic check and is still the wrong peer.
//! * **Equality** — did the peer's published lengths change since they were
//!   measured? Same count, same order, same presence, same length, term by
//!   term.
//!
//! Either question answered wrong refuses the **whole** snapshot. A snapshot
//! that dropped the peer that moved and published the rest would be a roster
//! that never existed at any instant, which is a worse answer than no roster.
//!
//! # What a refusal costs
//!
//! Nothing stays acquired. Refusal drops the plan, and with it the staging
//! lease, all four leases `commit` took by value, and any rows built before the
//! mismatch — so the provider returns to exactly where it stood before
//! [`JoinedNetwork::plan_peers`](crate::JoinedNetwork::plan_peers)
//! was called. This is a release, not an absence of construction: capacity was
//! genuinely admitted and genuinely handed back.
//!
//! That holds for a refusal raised *after* the line lease has been narrowed
//! too. `transition` moves the reservation rather than replacing it, so the
//! lease still drops as one thing whatever width it currently names.
//!
//! # Why the advertisement is not decoded
//!
//! A [`CapabilityAdvert`](crate::protocol::CapabilityAdvert) nests a
//! `serde_json::Value`, whose map, vector and string capacities are serde_json's
//! and std's business rather than a function of the encoded bytes. There is no
//! number a plan could quote for it and stand behind. The retained encoded form
//! *does* have exactly one size, so this module carries the peer's own canonical
//! bytes through to the wire verbatim and never builds the typed value at all.
//! The published JSON is byte-for-byte what the decoded round trip produces,
//! because the bytes are what the decoded value re-encodes to.

use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

use crate::engine::connection::{PeerStatus, PeerView};
use crate::engine::ladder::ConnectionTier;
use crate::engine::peer_registry::{PeerOwnerToken, PeerRegistry};
use crate::identity::{display_suffix_bytes, DISPLAY_SUFFIX_CHARS};
use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};
use crate::transport::{IceCandidateStats, SelectedCandidatePair};

/// Passes an advertisement copy makes over its own bytes: one to settle that
/// they are UTF-8, one to settle that they are JSON.
///
/// The copy itself is a third walk, but a `memcpy` of a byte slice is not the
/// same kind of work as either validation and is not charged as if it were.
const ADVERT_VALIDATION_PASSES: u64 = 2;

/// Passes the line seam makes over the built answer: one to count its encoded
/// width before publication, one to encode it.
///
/// Charged into the same work claim as the advertisement validations, because
/// it is the same kind of thing — transient CPU over bytes whose length a peer
/// chose — and charged against the *ceiling*, since that is the most either
/// pass can walk.
const LINE_ENCODE_PASSES: u64 = 2;

/// Allocations one non-empty boxed slice owns: its buffer.
const BOXED_SLICE_ALLOCATIONS: u64 = 1;

/// Widest expansion one source byte can suffer inside a JSON string: a control
/// character rendered `\u00XX`.
const JSON_ESCAPE_CEILING: usize = 6;

/// Widest JSON the fixed-shape half of one row serializes to.
///
/// Every field name, every separator, the braces, and the widest value each
/// non-string field can take — the status and tier tags, the candidate-count
/// objects at `u32::MAX`, the skew at `i64::MIN`, every `bool` at `false`, the
/// selected pair present, and every string field at its *empty or absent* form.
///
/// A bound, not an exact figure, and deliberately slack. It is proven rather
/// than asserted: `v4_r3_core_f7_the_row_ceiling_covers_the_widest_fixed_row`
/// builds the widest such row and measures it. The variable string and
/// advertisement terms are added *on top* of this, so each of them is counted
/// once more than it needs to be — which is the safe direction for a ceiling
/// and the reason this composition needs no per-field bookkeeping.
const PEER_ROW_FIXED_CEILING: usize = 1024;

/// A peer's display tag, inline.
///
/// Five ASCII bytes with no heap behind them, which is the point: the `String`
/// [`crate::identity::display_suffix`] returns would cost a byte term and an
/// allocation on every row, for a value whose width is fixed at compile time.
/// Serializes as the string it is, so the wire result is unchanged.
struct DisplaySuffix([u8; DISPLAY_SUFFIX_CHARS]);

impl Serialize for DisplaySuffix {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(
            std::str::from_utf8(&self.0).expect("a display suffix is uppercase hex, so ASCII"),
        )
    }
}

/// One peer as a funded snapshot publishes it.
///
/// Field for field [`crate::handle::PeerInfo`], in its declaration order, with
/// two representation differences and no wire differences:
///
/// * `capabilities` carries the peer's canonical encoded advertisement instead
///   of a decoded `CapabilityAdvert`. `Box<RawValue>` serializes those bytes
///   verbatim.
/// * `device_suffix` is the inline tag rather than a `String`.
///
/// `PeerInfo` derives `Serialize` with no `skip_serializing_if` on any field, so
/// every field below is present in the output and an absent advertisement
/// serializes as `null` rather than being omitted.
///
/// Module-private, and never handed out: a row exists only between
/// `PreparedPeerSnapshot::commit` building it and that same call encoding it.
/// What leaves this module is the encoded line.
///
/// Every owned string is a `Box<str>` and not a `String`. A `String` carries a
/// capacity that `to_owned` and `clone` guarantee only to be *at least* the
/// length, so a row built from `String`s could not be charged exactly for what
/// it holds. A `Box<str>` has no capacity: its layout is its length.
struct PublishedPeer {
    device_id: Box<str>,
    status: PeerStatus,
    tier: ConnectionTier,
    rtt_ms: Option<u32>,
    clock_skew_ms: Option<i64>,
    label: Box<str>,
    capabilities: Option<Box<RawValue>>,
    local_shelved: bool,
    remote_shelved: bool,
    authenticated: bool,
    device_suffix: DisplaySuffix,
    verification_code_received: Option<Box<str>>,
    verification_code_sent: Option<Box<str>>,
    local_approve_sent: bool,
    remote_approve_seen: bool,
    needs_turn: bool,
    local_candidates: IceCandidateStats,
    remote_candidates: IceCandidateStats,
    selected_pair: Option<SelectedCandidatePair>,
}

// Written out rather than derived so the field order and the `None`-is-`null`
// requirement above are enforced here instead of being a property of a derive
// nobody re-reads. A field added to `PeerInfo` and not added here is a control
// failure, not a silent omission.
impl Serialize for PublishedPeer {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut row = serializer.serialize_struct("PeerInfo", 19)?;
        row.serialize_field("device_id", &self.device_id)?;
        row.serialize_field("status", &self.status)?;
        row.serialize_field("tier", &self.tier)?;
        row.serialize_field("rtt_ms", &self.rtt_ms)?;
        row.serialize_field("clock_skew_ms", &self.clock_skew_ms)?;
        row.serialize_field("label", &self.label)?;
        row.serialize_field("capabilities", &self.capabilities)?;
        row.serialize_field("local_shelved", &self.local_shelved)?;
        row.serialize_field("remote_shelved", &self.remote_shelved)?;
        row.serialize_field("authenticated", &self.authenticated)?;
        row.serialize_field("device_suffix", &self.device_suffix)?;
        row.serialize_field(
            "verification_code_received",
            &self.verification_code_received,
        )?;
        row.serialize_field("verification_code_sent", &self.verification_code_sent)?;
        row.serialize_field("local_approve_sent", &self.local_approve_sent)?;
        row.serialize_field("remote_approve_seen", &self.remote_approve_seen)?;
        row.serialize_field("needs_turn", &self.needs_turn)?;
        row.serialize_field("local_candidates", &self.local_candidates)?;
        row.serialize_field("remote_candidates", &self.remote_candidates)?;
        row.serialize_field("selected_pair", &self.selected_pair)?;
        row.end()
    }
}

/// Every heap length one published row will hold.
///
/// `PartialEq` is the pass-B equality check, and it is derived rather than
/// hand-written so a term added to the measurement cannot be left out of the
/// comparison. `Option` carries presence, so a verification code that appeared
/// or disappeared between the passes is a difference even when a length would
/// coincidentally match.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PeerRowLengths {
    device_id: usize,
    label: usize,
    verification_code_received: Option<usize>,
    verification_code_sent: Option<usize>,
    /// The canonical encoded advertisement's length, if this peer's promoted
    /// session has heard one.
    capabilities: Option<usize>,
}

impl PeerRowLengths {
    /// Count what publishing this peer would retain, from one observation.
    ///
    /// Allocation-free, which is what lets it run before anything is funded and
    /// again inside the funded build without changing the amount owed.
    fn measure(view: PeerView<'_>) -> Self {
        Self {
            device_id: view.device_id.len(),
            label: view.data.label.len(),
            verification_code_received: view
                .data
                .verification_code_received
                .as_ref()
                .map(String::len),
            verification_code_sent: view.data.verification_code_sent.as_ref().map(String::len),
            capabilities: view
                .session
                .and_then(|app| app.capabilities_encoded())
                .map(<[u8]>::len),
        }
    }

    /// What this row retains in the typed claim: each owned string it holds.
    ///
    /// **Not** the row's own inline size. The rows live in one
    /// `Box<[PublishedPeer]>` whose whole layout is charged once, by
    /// `plus_boxed_slice::<PublishedPeer>`; adding `size_of::<PublishedPeer>()`
    /// here as well would bill every row's inline bytes twice.
    fn typed_terms(&self) -> std::result::Result<Terms, ResourceClaimArithmeticError> {
        Terms::default()
            .plus_boxed_str(self.device_id)?
            .plus_boxed_str(self.label)?
            .plus_optional_boxed_str(self.verification_code_received)?
            .plus_optional_boxed_str(self.verification_code_sent)
    }

    /// What this row retains in the output claim: the advertisement buffer, and
    /// nothing when there is no advertisement.
    ///
    /// The `Box<RawValue>` pointing at it is inline in the row and is already
    /// counted by the rows' boxed slice; charging it here would bill it twice.
    fn output_terms(&self) -> std::result::Result<Terms, ResourceClaimArithmeticError> {
        match self.capabilities {
            None => Ok(Terms::default()),
            Some(len) => Terms::default().plus(count_of(len)?, BOXED_SLICE_ALLOCATIONS),
        }
    }

    /// Widest JSON this row can serialize to.
    ///
    /// Allocation-free arithmetic over the measured lengths. Every string term
    /// allows for full `\u00XX` escaping of every byte, and each is added on top
    /// of a fixed part that already allowed for the empty or absent form — so
    /// this over-counts on purpose. A ceiling that was tight would have to model
    /// serde_json's escaping rules, and a snapshot that mispredicted them by one
    /// byte would be exactly the drift the line seam exists to catch.
    fn encoded_ceiling(&self) -> Option<usize> {
        let mut total = PEER_ROW_FIXED_CEILING;
        for len in [self.device_id, self.label] {
            total = total.checked_add(json_string_ceiling(len)?)?;
        }
        for len in [self.verification_code_received, self.verification_code_sent]
            .into_iter()
            .flatten()
        {
            total = total.checked_add(json_string_ceiling(len)?)?;
        }
        // The advertisement is copied verbatim, so it expands by nothing.
        match self.capabilities {
            None => Some(total),
            Some(len) => total.checked_add(len),
        }
    }

    /// The transient work this row costs: validating its copied advertisement,
    /// and the line seam's two walks over the width it may occupy.
    fn work(&self) -> std::result::Result<u64, ResourceClaimArithmeticError> {
        let overflow = ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::ParsingOrCpuWork,
        };
        let validation = match self.capabilities {
            None => 0,
            Some(len) => count_of(len)?
                .checked_mul(ADVERT_VALIDATION_PASSES)
                .ok_or(overflow)?,
        };
        let line = count_of(self.encoded_ceiling().ok_or(overflow)?)?
            .checked_mul(LINE_ENCODE_PASSES)
            .ok_or(overflow)?;
        validation.checked_add(line).ok_or(overflow)
    }
}

/// Widest JSON a string of `len` source bytes can serialize to: every byte
/// escaped, plus the two quotes.
fn json_string_ceiling(len: usize) -> Option<usize> {
    len.checked_mul(JSON_ESCAPE_CEILING)?.checked_add(2)
}

/// A running claim total in the two dimensions retention is charged in.
///
/// Summed as plain integers and turned into a [`ResourceClaim`] once, rather
/// than composing claims per term: the arithmetic is the same and this way an
/// overflow names the dimension that overflowed instead of the addition that
/// noticed.
#[derive(Clone, Copy, Default)]
struct Terms {
    bytes: u64,
    allocations: u64,
}

impl Terms {
    fn plus(
        self,
        bytes: u64,
        allocations: u64,
    ) -> std::result::Result<Self, ResourceClaimArithmeticError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(bytes)
                .ok_or(ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                })?,
            allocations: self.allocations.checked_add(allocations).ok_or(
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                },
            )?,
        })
    }

    fn plus_terms(self, other: Self) -> std::result::Result<Self, ResourceClaimArithmeticError> {
        self.plus(other.bytes, other.allocations)
    }

    /// One `Box<str>` of `len` bytes: its bytes, and one allocation.
    ///
    /// Exact rather than a lower bound, and that is a property of the *type*.
    /// A `Box<str>` has no capacity field and no spare room — its allocation is
    /// laid out for its length and deallocated against that same layout. A
    /// `String` holding the same text would carry a capacity that `to_owned`,
    /// `clone` and `with_capacity` all guarantee only to be *at least* `len`,
    /// which is why no published field is one.
    ///
    /// An empty `Box<str>` charges nothing: a zero-length slice needs no
    /// allocation and is represented by a dangling pointer.
    fn plus_boxed_str(self, len: usize) -> std::result::Result<Self, ResourceClaimArithmeticError> {
        if len == 0 {
            return Ok(self);
        }
        self.plus(count_of(len)?, 1)
    }

    fn plus_optional_boxed_str(
        self,
        len: Option<usize>,
    ) -> std::result::Result<Self, ResourceClaimArithmeticError> {
        match len {
            None => Ok(self),
            Some(len) => self.plus_boxed_str(len),
        }
    }

    /// One `Box<[T]>` of exactly `len` elements, or nothing when it is empty.
    ///
    /// Exact for the same reason as [`Self::plus_boxed_str`]: a boxed slice's
    /// layout is `len * size_of::<T>()` and there is nowhere for slack to hide.
    /// The `Vec` that builds one is transient and `into_boxed_slice` shrinks it
    /// to exactly this, so what a caller funds here is what the plan retains —
    /// unlike `Vec::with_capacity`, whose contract is *at least*.
    fn plus_boxed_slice<T>(
        self,
        len: usize,
    ) -> std::result::Result<Self, ResourceClaimArithmeticError> {
        if len == 0 {
            return Ok(self);
        }
        let bytes = size_of_as_count::<T>()?.checked_mul(count_of(len)?).ok_or(
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            },
        )?;
        self.plus(bytes, BOXED_SLICE_ALLOCATIONS)
    }

    fn claim(self) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, self.bytes),
            (ResourceClass::OpaqueDependencyResidual, self.allocations),
        ])
    }
}

fn count_of(value: usize) -> std::result::Result<u64, ResourceClaimArithmeticError> {
    u64::try_from(value).map_err(|_| ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    })
}

fn size_of_as_count<T>() -> std::result::Result<u64, ResourceClaimArithmeticError> {
    count_of(std::mem::size_of::<T>())
}

/// Why a funded peers snapshot refused to produce one.
///
/// Carries no device id and no peer-supplied text, deliberately. Naming the
/// peer that moved would mean retaining a copy of its id on a path whose whole
/// point is that it acquired nothing — and the answer a caller acts on is the
/// same either way: this snapshot is void, take another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerSnapshotRefusal {
    /// A count or length overflowed the claim representation.
    Unrepresentable,
    /// A lease supplied to `commit` is not the one this plan quoted.
    WrongLease,
    /// A staged peer is no longer the installed peer under its device id.
    MembershipChanged,
    /// A staged peer's published lengths changed between the two passes.
    PeerChanged,
    /// The built rows encode wider than the line ceiling that was admitted.
    ///
    /// Retention and encoded width are different measurements: two rows can
    /// hold the same bytes and serialize to different lengths. This is that
    /// gap, caught before publication rather than during it.
    LineWiderThanAdmitted,
    /// The provider would not narrow the line lease to the counted width.
    ///
    /// The admission was for a ceiling and the line turned out shorter, so the
    /// surplus has to go back before the snapshot can claim its lease is exact.
    /// A provider that refuses that leaves this path with a lease it cannot
    /// honestly describe, so it publishes nothing instead.
    LineNotReleasable,
    /// A retained advertisement did not re-validate as JSON.
    ///
    /// Reachable only if the encoded form a session retained stopped being what
    /// it was encoded from, which is a defect in the retention path rather than
    /// a condition a peer can drive.
    AdvertNotJson,
}

impl PeerSnapshotRefusal {
    pub const fn message(&self) -> &'static str {
        match self {
            Self::Unrepresentable => "the peers snapshot does not fit the claim representation",
            Self::WrongLease => "a lease supplied to the peers snapshot is not the planned claim",
            Self::MembershipChanged => "a planned peer was replaced before the snapshot was built",
            Self::PeerChanged => "a planned peer changed before the snapshot was built",
            Self::LineWiderThanAdmitted => {
                "the peers snapshot encodes wider than the admitted line ceiling"
            }
            Self::LineNotReleasable => {
                "the peers snapshot line lease could not be narrowed to its counted width"
            }
            Self::AdvertNotJson => "a retained capability advertisement is not valid JSON",
        }
    }
}

impl std::fmt::Display for PeerSnapshotRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for PeerSnapshotRefusal {}

impl From<ResourceClaimArithmeticError> for PeerSnapshotRefusal {
    fn from(_: ResourceClaimArithmeticError) -> Self {
        Self::Unrepresentable
    }
}

impl From<PeerSnapshotRefusal> for crate::error::Error {
    fn from(refusal: PeerSnapshotRefusal) -> Self {
        Self::Transport(refusal.message().to_string())
    }
}

/// The count, before it becomes an allocation.
///
/// A step of its own because the staged slices are themselves a claim, and a
/// snapshot that allocated them first and asked afterwards would have already
/// spent the thing it was asking about. `len` on the registry answers without
/// allocating, so this holds a number and a borrow and nothing else.
///
/// Deliberately **not** `#[must_use]`, unlike the two values downstream of it:
/// nothing has been acquired or built at this point, so dropping one discards a
/// number. A lint here would fire on code that has done nothing wrong.
pub struct PeerSnapshotStaging<'a> {
    registry: &'a PeerRegistry,
    counted: usize,
}

impl<'a> PeerSnapshotStaging<'a> {
    pub(super) fn new(registry: &'a PeerRegistry) -> Self {
        Self {
            registry,
            counted: registry.len(),
        }
    }

    /// How many peers this snapshot will be about, at most.
    pub const fn counted(&self) -> usize {
        self.counted
    }

    /// What staging costs: the owner tokens and their measurements, each in a
    /// boxed slice of exactly the counted length.
    pub fn membership_claim(&self) -> std::result::Result<ResourceClaim, PeerSnapshotRefusal> {
        Ok(Terms::default()
            .plus_boxed_slice::<PeerOwnerToken>(self.counted)?
            .plus_boxed_slice::<PeerRowLengths>(self.counted)?
            .claim()?)
    }

    /// Stage the membership and measure it — pass A.
    ///
    /// `membership` must be a lease for exactly [`Self::membership_claim`].
    /// Validated before anything is staged, so a caller that funded a different
    /// claim gets a refusal rather than a snapshot backed by the wrong
    /// reservation.
    ///
    /// Refuses if the roster shrank between the count and the staging. That is
    /// the same all-or-nothing rule pass B applies, moved to the first moment it
    /// can be applied: holding fewer rows than were funded would make the
    /// membership claim an over-estimate, and "exact" has to mean exact in both
    /// directions or it means nothing.
    pub fn stage(
        self,
        membership: ResourceLease,
    ) -> std::result::Result<PreparedPeerSnapshot<'a>, PeerSnapshotRefusal> {
        if membership.claim() != self.membership_claim()? {
            return Err(PeerSnapshotRefusal::WrongLease);
        }
        let owners = self.registry.stage_owners(self.counted);
        if owners.len() != self.counted {
            return Err(PeerSnapshotRefusal::MembershipChanged);
        }
        let lengths: Box<[PeerRowLengths]> = owners
            .iter()
            .map(|owner| owner.peer().with_peer_view(PeerRowLengths::measure))
            .collect();
        // Every subsequent claim is a fold over `lengths`, so it is derived
        // once here and never recomputed from a second observation.
        let mut work = 0u64;
        let mut typed = Terms::default().plus_boxed_slice::<PublishedPeer>(owners.len())?;
        let mut output = Terms::default();
        // Two brackets and at most one separator per row. A ceiling, like every
        // other line term.
        let mut line_ceiling = owners.len().checked_add(2).ok_or(unrepresentable_line())?;
        for row in &lengths {
            work = work
                .checked_add(row.work()?)
                .ok_or(ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::ParsingOrCpuWork,
                })?;
            typed = typed.plus_terms(row.typed_terms()?)?;
            output = output.plus_terms(row.output_terms()?)?;
            line_ceiling = line_ceiling
                .checked_add(row.encoded_ceiling().ok_or(unrepresentable_line())?)
                .ok_or(unrepresentable_line())?;
        }
        Ok(PreparedPeerSnapshot {
            registry: self.registry,
            owners,
            lengths,
            _membership: membership,
            work: ResourceClaim::single(ResourceClass::ParsingOrCpuWork, work),
            typed: typed.claim()?,
            output: output.claim()?,
            line_ceiling,
            line: Terms::default()
                .plus_boxed_slice::<u8>(line_ceiling)?
                .claim()?,
        })
    }
}

fn unrepresentable_line() -> ResourceClaimArithmeticError {
    ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    }
}

/// A measured peers snapshot, funded for its membership and not yet for its
/// contents.
///
/// Holds the borrowed registry it measured against, not a key it could look one
/// up in again: [`Self::commit`] settles identity against the exact tokens this
/// plan staged, so there is no supplied input for a caller to vary and no way
/// to commit this plan against a roster it never measured.
///
/// `owners` and `lengths` are index-aligned by construction — `lengths` is
/// built by one pass over `owners` in [`PeerSnapshotStaging::stage`] and neither
/// is mutated afterwards. They are two slices rather than one because staging
/// them together would mean measuring peer state while the registry's shard
/// guard was still held.
///
/// Both are boxed slices: their layout is a function of their length alone, so
/// the membership claim is what this plan holds rather than a lower bound on it.
#[must_use = "a prepared snapshot holds the membership lease its measurements \
              were funded under; dropping it without committing releases that \
              funding and discards the measurements"]
pub struct PreparedPeerSnapshot<'a> {
    registry: &'a PeerRegistry,
    owners: Box<[PeerOwnerToken]>,
    lengths: Box<[PeerRowLengths]>,
    /// Held for its `Drop`. Funds both slices above for exactly as long as
    /// this plan exists — including the refusal paths, which drop it.
    _membership: ResourceLease,
    work: ResourceClaim,
    typed: ResourceClaim,
    output: ResourceClaim,
    line_ceiling: usize,
    line: ResourceClaim,
}

impl PreparedPeerSnapshot<'_> {
    /// How many peers this snapshot will publish.
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// The validation passes over peer-controlled advertisement bytes.
    ///
    /// Transient. The lease funding this is released inside [`Self::commit`]
    /// once the copies are made, because nothing retains the work.
    pub const fn work_claim(&self) -> ResourceClaim {
        self.work
    }

    /// The published rows and the owned strings in them.
    pub const fn typed_retention_claim(&self) -> ResourceClaim {
        self.typed
    }

    /// The advertisement buffers — the peer-chosen term.
    pub const fn output_retention_claim(&self) -> ResourceClaim {
        self.output
    }

    /// Widest the published line can be, in bytes.
    ///
    /// Derived in pass A by arithmetic over the measured lengths — nothing is
    /// serialized to obtain it and nothing is allocated. A number and only a
    /// number: a caller admits a line by funding [`Self::line_claim`] for this
    /// width, and [`Self::commit`] then refuses to publish anything wider.
    ///
    /// Deliberately not tight. Two rows that retain identical bytes can encode
    /// to different widths — a label of the same length whose characters need
    /// escaping, a skew that grew a digit — and a ceiling that tried to predict
    /// that exactly would be the thing most likely to be wrong. What makes the
    /// seam sound is not the ceiling's tightness but that `commit` counts the
    /// real width and compares.
    pub const fn encoded_line_ceiling(&self) -> usize {
        self.line_ceiling
    }

    /// The line buffer, at [`Self::encoded_line_ceiling`] bytes.
    ///
    /// **Scope: the JSON peers array and nothing else.** These bytes are what
    /// `[{…},{…}]` costs — the same array
    /// [`crate::handle::JoinedNetwork::peers`] serializes to. A daemon that
    /// wraps them in an envelope, a framing header, a trailing newline or a
    /// response object is adding width this claim does not cover and must fund
    /// that itself. Core cannot size a wrapper it has never seen.
    ///
    /// This is an admission ceiling, not the final charge. [`Self::commit`]
    /// narrows the lease to the width it actually counted, so a snapshot never
    /// retains a reservation for slack the ceiling allowed and the encoding did
    /// not use.
    pub const fn line_claim(&self) -> ResourceClaim {
        self.line
    }

    /// Build the snapshot — pass B.
    ///
    /// Each lease must be for exactly the claim of the same name, and all four
    /// are validated before the first row is built. A caller that funded a
    /// different plan's numbers is refused here rather than building under a
    /// reservation that was never taken for this work.
    ///
    /// Every row is settled for identity and for equality inside the same
    /// observation that builds it, so nothing can change between the check and
    /// the copy it authorized.
    ///
    /// **Line admission is the last gate, and it is before publication.** Once
    /// the rows exist, their real encoded width is counted — without allocating
    /// — and compared against the ceiling the `line` lease was taken for. A
    /// snapshot that measured the same retention but encodes wider than
    /// admitted is refused and rolled back here, rather than handed to a caller
    /// who would discover it while writing past the buffer it funded.
    pub fn commit(
        self,
        work: ResourceLease,
        typed: ResourceLease,
        output: ResourceLease,
        mut line: ResourceLease,
    ) -> std::result::Result<FundedPeerSnapshot, PeerSnapshotRefusal> {
        if work.claim() != self.work
            || typed.claim() != self.typed
            || output.claim() != self.output
            || line.claim() != self.line
        {
            return Err(PeerSnapshotRefusal::WrongLease);
        }
        let mut rows = Vec::with_capacity(self.owners.len());
        for (owner, planned) in self.owners.iter().zip(&self.lengths) {
            // Identity first: a replacement under the same device id is a
            // different peer, and no amount of length agreement makes it the
            // one that was measured.
            let Some(peer) = self.registry.get_if_current(owner) else {
                return Err(PeerSnapshotRefusal::MembershipChanged);
            };
            // Under the observation: settle equality, copy. Nothing here
            // validates, so the peer's state guard and its promoted-session
            // slot are held for a `memcpy` and no longer.
            let BuiltRow { mut row, advert } =
                peer.with_peer_view(|view| build_row(view, *planned))?;
            // Outside it: validate. Two passes over peer-chosen bytes is the
            // work the work claim paid for, and it is the part that must not
            // run while a peer's own writers are blocked behind it.
            if let Some(bytes) = advert {
                row.capabilities = Some(validated_raw_advert(bytes)?);
            }
            rows.push(row);
        }
        let rows = rows.into_boxed_slice();

        // Line admission, before anything is published. The first of the two
        // funded line walks: it visits every row and writes nowhere.
        let encoded_len = encoded_line_len(&rows).ok_or(PeerSnapshotRefusal::Unrepresentable)?;
        if encoded_len > self.line_ceiling {
            return Err(PeerSnapshotRefusal::LineWiderThanAdmitted);
        }

        // The ceiling was for admission; this is for retention. Now that the
        // real width is known, the line lease is transitioned down to it, so
        // what stays reserved is the buffer that will exist rather than the
        // slack the ceiling allowed for. A refusal here leaves the lease at the
        // ceiling — `transition` is atomic — and the whole snapshot is voided,
        // which is the same all-or-nothing rule as everywhere else here.
        let exact_line = Terms::default()
            .plus_boxed_slice::<u8>(encoded_len)?
            .claim()?;
        line.transition(exact_line)
            .map_err(|_| PeerSnapshotRefusal::LineNotReleasable)?;

        // The second funded line walk, and the only one that writes. Done here
        // and exactly once: a `&self` encode that a caller could run repeatedly
        // would make a one-pass work claim a fiction, so the bytes are produced
        // under the work lease that paid for them and the rows are gone before
        // anybody else can ask.
        let encoded = encode_line_exact(&rows, encoded_len).ok_or(
            // The count and the encode disagreed, which would mean a
            // `Serialize` impl in this module is not deterministic.
            PeerSnapshotRefusal::Unrepresentable,
        )?;

        // The answer is the bytes. The rows were the intermediate the typed and
        // output claims funded, and they end here, together with those claims —
        // holding either past this point would be charging for a representation
        // that no longer exists.
        drop(rows);
        drop(output);
        drop(typed);
        // Both funded walks are done, so the work is done.
        drop(work);
        Ok(FundedPeerSnapshot {
            peers: self.owners.len(),
            encoded,
            _line: line,
        })
    }
}

/// Serialize into one buffer of exactly `len` bytes.
///
/// `None` if the encoding does not land on exactly `len`, which would mean the
/// count taken moments earlier disagrees with the encode. A refusal rather than
/// a short or reallocated line.
fn encode_line_exact(peers: &[PublishedPeer], len: usize) -> Option<Box<[u8]>> {
    let mut buffer = Vec::with_capacity(len);
    serde_json::to_writer(&mut buffer, peers).ok()?;
    (buffer.len() == len).then(|| buffer.into_boxed_slice())
}

/// Exactly how many bytes a built snapshot serializes to, without building the
/// bytes.
///
/// Concrete rather than generic, deliberately, for the reason
/// `crate::protocol`'s own counter states about its private twin: "counting is
/// free" is a claim about the `Serialize` impls being walked, not about the
/// writer. The impls walked here are this module's hand-written
/// [`PublishedPeer`] one and the derived ones it forwards to, all of which are
/// readable from here. A generic form would let a later caller hand it a type
/// nobody checked.
fn encoded_line_len(peers: &[PublishedPeer]) -> Option<usize> {
    struct CountingWriter(usize);

    impl std::io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.checked_add(buf.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "encoded length exceeds the addressable range",
                )
            })?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = CountingWriter(0);
    serde_json::to_writer(&mut counter, peers).ok()?;
    Some(counter.0)
}

/// One row as it leaves the observation: built, but not yet finished.
///
/// A named pair rather than a tuple, because the two halves are in different
/// states and the distinction is the whole point of the split. `row` is
/// complete except for its advertisement; `advert` is that advertisement, still
/// an unvalidated copy, waiting for the caller to validate it once the peer's
/// locks are released. Returning `(PublishedPeer, Option<Box<[u8]>>)` said the
/// same thing in a shape a reader has to decode positionally.
struct BuiltRow {
    row: PublishedPeer,
    /// `None` when this peer's session has heard no advertisement — not when
    /// one is merely still pending.
    advert: Option<Box<[u8]>>,
}

/// Build one published row from the observation that just re-measured it,
/// leaving the advertisement as an unvalidated copy for the caller to finish
/// outside the observation.
///
/// The equality check and the copying share a view deliberately: checking under
/// one observation and copying under another would let a peer change in between
/// and be published at a size nobody funded. The *validation* deliberately does
/// not — see [`validated_raw_advert`], which the caller runs once this view is
/// released.
///
/// The row comes back with `capabilities: None` whether or not this peer
/// advertised. [`BuiltRow::advert`], not the row, is what says which: a row that
/// carried a half-built advertisement would be a value that is briefly a lie
/// about the peer.
fn build_row(
    view: PeerView<'_>,
    planned: PeerRowLengths,
) -> std::result::Result<BuiltRow, PeerSnapshotRefusal> {
    if PeerRowLengths::measure(view) != planned {
        return Err(PeerSnapshotRefusal::PeerChanged);
    }
    let data = view.data;
    // A `Box<[u8]>`, not a `Vec`: the copy must end up in a buffer laid out for
    // its length, because that is the layout the output claim was taken for and
    // the only one whose capacity cannot exceed it.
    let copied: Option<Box<[u8]>> = view
        .session
        .and_then(|app| app.capabilities_encoded())
        .map(Box::from);
    Ok(BuiltRow {
        row: PublishedPeer {
            device_id: Box::from(view.device_id),
            status: data.status,
            tier: data.tier,
            rtt_ms: data.rtt_ms,
            clock_skew_ms: data.clock_skew_ms,
            label: Box::from(data.label.as_str()),
            capabilities: None,
            local_shelved: data.local_shelved,
            remote_shelved: data.remote_shelved,
            authenticated: data.authenticated,
            device_suffix: DisplaySuffix(display_suffix_bytes(
                crate::signing::pubkey_part(view.device_id).as_bytes(),
            )),
            verification_code_received: data.verification_code_received.as_deref().map(Box::from),
            verification_code_sent: data.verification_code_sent.as_deref().map(Box::from),
            local_approve_sent: data.local_approve_sent,
            remote_approve_seen: data.remote_approve_seen,
            needs_turn: data.no_turn_diag_emitted,
            // `IceCandidateStats` is not `Copy`, so this is a clone. It is five
            // `u32`s with no heap under them: no byte term, no allocation, and
            // nothing for the typed claim to have counted.
            local_candidates: data.diag.local_candidates.clone(),
            remote_candidates: data.diag.remote_candidates.clone(),
            selected_pair: data.selected_pair,
        },
        advert: copied,
    })
}

/// Turn one copied advertisement into the carrier that publishes it.
///
/// Takes the boxed buffer [`build_row`] already made, and adds no allocation of
/// its own. The chain is written this way to keep capacity pinned to length at
/// every step, because a `Vec` or `String` obtained any other way would only
/// promise *at least* the length it holds:
///
/// * `<[u8]>::into_vec` rebuilds a `Vec` from a boxed slice's own layout, so
///   its capacity **equals** its length by construction rather than by an
///   allocator's choice.
/// * `String::from_utf8` validates and takes that `Vec` whole, capacity
///   included, rather than copying into a new one.
/// * `RawValue::from_string` validates the JSON and, when the text has no
///   surrounding whitespace to trim, hands the same buffer on through
///   `into_boxed_str` — which reallocates only if capacity exceeds length, and
///   it cannot here. Retained advertisements are canonical: they were produced
///   by `encode_exact` at a counted length, so the no-trim condition holds by
///   construction rather than by luck.
///
/// Both validations are what the work claim paid for, and both run here rather
/// than inside `build_row` — which means they run with the peer's state guard
/// and promoted-session slot already released. Two passes over bytes a peer
/// chose the length of is exactly the work that must not be done while that
/// peer's own writers are queued behind it.
fn validated_raw_advert(
    copied: Box<[u8]>,
) -> std::result::Result<Box<RawValue>, PeerSnapshotRefusal> {
    let buffer = copied.into_vec();
    debug_assert_eq!(
        buffer.capacity(),
        buffer.len(),
        "a vector rebuilt from a boxed slice carries that slice's exact layout"
    );
    let text = String::from_utf8(buffer).map_err(|_| PeerSnapshotRefusal::AdvertNotJson)?;
    RawValue::from_string(text).map_err(|_| PeerSnapshotRefusal::AdvertNotJson)
}

/// A peers snapshot, built and paid for.
///
/// Serializes as the array [`crate::handle::JoinedNetwork::peers`] returns, row
/// for row and byte for byte. The rows are borrowed, never handed out owned:
/// the leases that paid for them belong to this value, and handing a row out
/// would separate the bytes from the reservation holding them.
///
/// **The answer is bytes, not rows.** The rows were the intermediate the typed
/// and output claims funded; they were serialized once inside `commit`, under
/// the work lease that paid for that walk, and dropped there along with both of
/// those claims. What survives is the encoded line and the lease sized for it.
///
/// That is deliberate, and it is what makes the work claim honest. A funded
/// snapshot that kept its rows and offered `encode(&self)` would let a caller
/// run the encoding pass any number of times, while the work claim had paid for
/// one — so this type does not offer one. Encoding again is not refused here; it
/// is unrepresentable.
///
/// The line lease is for exactly [`Self::bytes`]`.len()`, not for the ceiling
/// that admitted it: `commit` transitions it down to the counted width once that
/// width is known, so nothing stays reserved for slack that was never used.
#[must_use = "a funded snapshot holds the line lease its encoded bytes were \
              produced under; dropping it releases that lease and discards the \
              answer, which cannot be produced again without a new plan"]
pub struct FundedPeerSnapshot {
    /// How many peers the line describes. A count, not a collection: the rows
    /// themselves are gone.
    peers: usize,
    encoded: Box<[u8]>,
    /// Held for its `Drop`, and sized for exactly the buffer beside it.
    _line: ResourceLease,
}

impl FundedPeerSnapshot {
    /// How many peers the published line describes.
    pub const fn len(&self) -> usize {
        self.peers
    }

    pub const fn is_empty(&self) -> bool {
        self.peers == 0
    }

    /// The published line, borrowed.
    ///
    /// The same bytes `serde_json` produces for the `Vec<PeerInfo>` that
    /// [`crate::handle::JoinedNetwork::peers`] returns. Borrowed and never
    /// handed out owned: the lease that paid for them belongs to this value.
    pub fn bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Exactly how many bytes [`Self::bytes`] is.
    ///
    /// Counted from the rows before they were encoded, and equal to the encoded
    /// result by construction — `commit` refuses rather than returning a value
    /// whose count and content disagree.
    pub const fn encoded_len(&self) -> usize {
        self.encoded.len()
    }
}

#[cfg(test)]
mod peers_snapshot_controls {
    use std::sync::Arc;

    use super::*;
    use crate::engine::connection::PeerConnection;
    use crate::protocol::CapabilityAdvert;
    use crate::resource::provider::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceScope,
    };

    /// A provider with room to spare, so nothing below is refused for capacity
    /// and every ledger reading is about what this code took rather than about
    /// what the fixture allowed.
    fn ledger() -> (FiniteResourceProvider, ResourceProviderPort, ResourceScope) {
        let provider = FiniteResourceProvider::new(
            ResourceClaim::try_from_entries([
                (ResourceClass::AccountedMemoryBytes, 1 << 20),
                (ResourceClass::OpaqueDependencyResidual, 4096),
                (ResourceClass::ParsingOrCpuWork, 1 << 20),
            ])
            .expect("the fixture grant is representable"),
        );
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let process_scope = port.process_scope();
        let scope = port
            .create_scope(&process_scope)
            .expect("one fixture scope");
        (provider, port, scope)
    }

    fn acquire(
        port: &ResourceProviderPort,
        scope: &ResourceScope,
        claim: ResourceClaim,
    ) -> ResourceLease {
        port.acquire(scope, ResourceAuthorityClass::Admitted, claim)
            .expect("the fixture grant funds this claim")
    }

    /// What the ledger reads while leases for exactly `claims` are held, taken
    /// by holding them and putting them back.
    ///
    /// Measured rather than restated: a control that recomputed this from the
    /// claim plus its own idea of the provider's per-reservation record would be
    /// asserting its own arithmetic against itself.
    ///
    /// **It acquires real leases to measure with, so it moves the ledger while
    /// it runs.** Call it only when the provider reads what the comparison's
    /// other side was taken from — in practice, at baseline. Calling it while
    /// the value under test is still alive measures that value *plus* the
    /// probe, which is a state production never reaches. Take the live reading
    /// first, release the value, then probe.
    fn footprint_of(
        provider: &FiniteResourceProvider,
        port: &ResourceProviderPort,
        scope: &ResourceScope,
        claims: &[ResourceClaim],
    ) -> ResourceClaim {
        let held: Vec<ResourceLease> = claims
            .iter()
            .map(|claim| acquire(port, scope, *claim))
            .collect();
        let reading = provider.in_use();
        drop(held);
        reading
    }

    fn peer_with(device_id: &str, label: &str, code: Option<&str>) -> Arc<PeerConnection> {
        let peer = Arc::new(PeerConnection::new(device_id.to_string(), None));
        {
            let mut state = peer.state.write();
            state.label = label.to_string();
            state.verification_code_received = code.map(str::to_string);
        }
        peer
    }

    fn advert() -> CapabilityAdvert {
        CapabilityAdvert {
            tags: vec!["transcribe".to_string(), "host-files".to_string()],
            app_version: Some("0.3.2".to_string()),
            extra: serde_json::json!({ "slots": 3, "modes": ["fast", "exact"], "beta": null }),
        }
    }

    /// The four leases a plan quotes, in the order `commit` takes them.
    struct Funding {
        work: ResourceLease,
        typed: ResourceLease,
        output: ResourceLease,
        line: ResourceLease,
    }

    /// The staged registry's plan and the four leases the plan quoted.
    fn planned<'a>(
        registry: &'a PeerRegistry,
        port: &ResourceProviderPort,
        scope: &ResourceScope,
    ) -> (PreparedPeerSnapshot<'a>, Funding) {
        let staging = PeerSnapshotStaging::new(registry);
        let membership = acquire(
            port,
            scope,
            staging.membership_claim().expect("a small roster plans"),
        );
        let prepared = staging.stage(membership).expect("the planned lease stages");
        let funding = Funding {
            work: acquire(port, scope, prepared.work_claim()),
            typed: acquire(port, scope, prepared.typed_retention_claim()),
            output: acquire(port, scope, prepared.output_retention_claim()),
            line: acquire(port, scope, prepared.line_claim()),
        };
        (prepared, funding)
    }

    /// Commit under exactly the funding a plan quoted.
    fn commit_funded(
        prepared: PreparedPeerSnapshot<'_>,
        funding: Funding,
    ) -> std::result::Result<FundedPeerSnapshot, PeerSnapshotRefusal> {
        prepared.commit(funding.work, funding.typed, funding.output, funding.line)
    }

    #[test]
    fn v4_r3_core_f7_a_funded_peers_commit_spends_exactly_its_plan() {
        let (provider, port, scope) = ledger();
        let registry = PeerRegistry::default();
        let _ = registry.install(peer_with("alpha", "Alpha", None));
        let _ = registry.install(peer_with("bravo", "", Some("12345")));
        let baseline = provider.in_use();

        // A first plan, only to learn what the three retained claims are, and
        // then dropped. What the ledger reads while leases for exactly those
        // three are held — and nothing else — is what a committed snapshot must
        // read.
        let (typed_claim, output_claim, line_claim) = {
            let staging = PeerSnapshotStaging::new(&registry);
            let claim = staging.membership_claim().expect("a two-peer roster plans");
            let prepared = staging
                .stage(acquire(&port, &scope, claim))
                .expect("the planned lease stages");
            (
                prepared.typed_retention_claim(),
                prepared.output_retention_claim(),
                prepared.line_claim(),
            )
        };
        assert_eq!(
            provider.in_use(),
            baseline,
            "a plan that is dropped rather than committed keeps nothing"
        );
        let retained_footprint = footprint_of(
            &provider,
            &port,
            &scope,
            &[typed_claim, output_claim, line_claim],
        );
        assert_eq!(provider.in_use(), baseline, "the probe put its leases back");

        let staging = PeerSnapshotStaging::new(&registry);
        assert_eq!(staging.counted(), 2, "both installed peers are counted");
        assert_eq!(
            provider.in_use(),
            baseline,
            "non-vacuity for everything below: counting moved the ledger not at \
             all, so the plan has built nothing to be measured against"
        );

        let membership_claim = staging.membership_claim().expect("a two-peer roster plans");
        let membership = acquire(&port, &scope, membership_claim);
        let prepared = staging.stage(membership).expect("the planned lease stages");
        assert_eq!(
            (
                prepared.typed_retention_claim(),
                prepared.output_retention_claim(),
                prepared.line_claim()
            ),
            (typed_claim, output_claim, line_claim),
            "planning the same unchanged roster quotes the same numbers"
        );
        let ceiling = prepared.encoded_line_ceiling();
        let work = acquire(&port, &scope, prepared.work_claim());
        let typed = acquire(&port, &scope, typed_claim);
        let output = acquire(&port, &scope, output_claim);
        let line = acquire(&port, &scope, line_claim);

        let funded = prepared
            .commit(work, typed, output, line)
            .expect("a roster that did not move commits");
        assert_eq!(funded.len(), 2);

        // The line seam, end to end. The counted width was inside the ceiling,
        // and the buffer is exactly that width.
        assert!(
            funded.encoded_len() <= ceiling,
            "the counted width was inside the admitted ceiling"
        );
        assert_eq!(
            funded.bytes().len(),
            funded.encoded_len(),
            "the line occupies exactly the width commit counted for it"
        );

        // Everything below compares against this one reading, taken while the
        // snapshot is live and *before* any probe runs. `footprint_of` acquires
        // real leases to measure with, so calling it here would add a second
        // reservation to the very reading under test — the ledger would report
        // the snapshot's lease plus the probe's, and the comparison would be
        // against a state that never exists in production.
        let live = provider.in_use();
        let written = funded.encoded_len();

        assert!(
            written < ceiling,
            "non-vacuity for the narrowing: the ceiling really was slack, so a \
             snapshot that kept its admission would read higher than one that \
             narrowed to what it wrote"
        );
        // `retained_footprint` was the reading with the *ceiling*-sized line
        // lease held alongside typed and output. A committed snapshot must not
        // still read as that, since it gave all three back and took a smaller
        // one. Comparing two saved readings, so this adds nothing to the ledger.
        assert_ne!(
            live, retained_footprint,
            "a committed snapshot is not still holding what it was funded to \
             build with"
        );

        drop(funded);
        assert_eq!(
            provider.in_use(),
            baseline,
            "dropping the snapshot returns every lease it was built under"
        );

        // Only now, back at baseline, is it safe to measure what one exact line
        // lease costs — the same starting point `live` was taken from.
        let one_exact_line = footprint_of(
            &provider,
            &port,
            &scope,
            &[Terms::default()
                .plus_boxed_slice::<u8>(written)
                .expect("the written width is representable")
                .claim()
                .expect("and is a claim")],
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "the probe put its own lease back before anything is compared"
        );

        // What a committed snapshot *retains* is the line lease, narrowed to the
        // width it actually wrote, and nothing else. Staging died with the plan;
        // work died with the walks; typed and output died with the rows. This is
        // the whole point of the shape: the answer is bytes, and only the bytes
        // are still funded.
        assert_eq!(
            live, one_exact_line,
            "a committed snapshot holds one lease, sized for the bytes it holds"
        );
    }

    #[test]
    fn v4_r3_core_f7_a_peers_commit_refuses_a_lease_it_did_not_plan() {
        let (provider, port, scope) = ledger();
        let registry = PeerRegistry::default();
        let _ = registry.install(peer_with("alpha", "Alpha", None));
        let baseline = provider.in_use();

        let (prepared, funding) = planned(&registry, &port, &scope);
        // Deliberately a *larger* claim: a build that skipped the check would
        // have had room to succeed under it.
        let wrong_typed = acquire(
            &port,
            &scope,
            prepared
                .typed_retention_claim()
                .checked_add(ResourceClaim::single(
                    ResourceClass::AccountedMemoryBytes,
                    1,
                ))
                .expect("the mismatched claim is representable"),
        );

        // Not `unwrap_err`: that would need `FundedPeerSnapshot: Debug`, and a
        // published projection has no business deriving one.
        match prepared.commit(funding.work, wrong_typed, funding.output, funding.line) {
            Ok(_snapshot) => panic!("a commit under an unplanned lease must refuse"),
            Err(refusal) => assert_eq!(refusal, PeerSnapshotRefusal::WrongLease),
        }
        drop(funding.typed);
        assert_eq!(
            provider.in_use(),
            baseline,
            "a refused commit hands back the staging lease and all four it was given"
        );
    }

    #[test]
    fn v4_r3_core_f7_a_same_size_replacement_voids_the_whole_snapshot() {
        let (provider, port, scope) = ledger();
        let registry = PeerRegistry::default();
        let _ = registry.install(peer_with("alpha", "Alpha", None));
        let _ = registry.install(peer_with("bravo", "Bravo", None));
        let baseline = provider.in_use();

        let (prepared, funding) = planned(&registry, &port, &scope);

        // A different peer that is indistinguishable by measurement: same
        // device id, same label, same everything a length can see. Only the
        // installation identity separates it from the one that was planned.
        let replacement = peer_with("alpha", "Alpha", None);
        // By device id, not by position: the staged order is the registry's
        // iteration order and this control must not depend on it.
        let staged = prepared
            .owners
            .iter()
            .position(|owner| owner.device_id() == "alpha")
            .expect("alpha is staged");
        assert_eq!(
            replacement.with_peer_view(PeerRowLengths::measure),
            prepared.lengths[staged],
            "non-vacuity: the replacement measures identically, so length \
             equality alone would have let it through"
        );
        let _ = registry.install(replacement);

        match commit_funded(prepared, funding) {
            Ok(_snapshot) => panic!("a replaced peer must void the snapshot"),
            Err(refusal) => assert_eq!(refusal, PeerSnapshotRefusal::MembershipChanged),
        }
        assert_eq!(
            provider.in_use(),
            baseline,
            "the rows built before the mismatch went back with everything else"
        );
    }

    #[test]
    fn v4_r3_core_f7_a_changed_peer_voids_the_whole_snapshot() {
        let (provider, port, scope) = ledger();
        let registry = PeerRegistry::default();
        let _ = registry.install(peer_with("alpha", "Alpha", None));
        let _ = registry.install(peer_with("bravo", "Bravo", None));
        let baseline = provider.in_use();

        let (prepared, funding) = planned(&registry, &port, &scope);

        // The same installation, at a size nobody funded.
        let installed = registry.get("bravo").expect("bravo is installed");
        installed.state.write().label = "Bravo, at greater length".to_string();

        match commit_funded(prepared, funding) {
            Ok(_snapshot) => panic!("a peer that changed size must void the snapshot"),
            Err(refusal) => assert_eq!(refusal, PeerSnapshotRefusal::PeerChanged),
        }
        assert_eq!(
            provider.in_use(),
            baseline,
            "a refusal partway through the roster still returns every lease"
        );
    }

    #[test]
    fn v4_r3_core_f7_a_raw_advert_copy_keeps_its_bytes_and_its_capacity() {
        let advert = advert();
        let len = advert
            .encoded_len()
            .expect("a control advertisement counts");
        let encoded = advert.encode_exact(len).expect("and encodes to that size");

        // The same two steps `build_row` and `commit` take, split the same way.
        let copied: Box<[u8]> = Box::from(&encoded[..]);
        assert_eq!(
            copied.len(),
            len,
            "the copy is laid out for the measured length"
        );
        // The property the exact charge rests on, observed rather than assumed:
        // a `Vec` rebuilt from a boxed slice has capacity *equal* to its length.
        // `Vec::with_capacity` promises only "at least", which is why the copy
        // is a boxed slice and not a vector in the first place.
        let reclaimed = copied.clone().into_vec();
        assert_eq!(
            reclaimed.capacity(),
            reclaimed.len(),
            "a vector rebuilt from a boxed slice carries no spare capacity, so \
             `into_boxed_str` downstream cannot reallocate"
        );

        let raw = validated_raw_advert(copied).expect("canonical bytes are JSON");
        assert_eq!(
            raw.get().as_bytes(),
            &encoded[..],
            "the carrier holds the peer's own bytes, not a re-encoding of them"
        );
        assert_eq!(
            raw.get().len(),
            len,
            "and holds exactly as many as were measured, which is the condition \
             under which `RawValue::from_string` hands the buffer on rather than \
             allocating a trimmed copy of it"
        );

        // The other branch, shown so the claim above is about these bytes
        // rather than about every input: padded text is *not* what the carrier
        // was handed, and it is the shape that would cost a second allocation.
        let padded = format!(" {} ", raw.get());
        let trimmed = RawValue::from_string(padded.clone()).expect("padded text is still JSON");
        assert!(
            trimmed.get().len() < padded.len(),
            "non-vacuity: a non-canonical input does take the copying branch"
        );
    }

    #[test]
    fn v4_r3_core_f7_the_funded_peer_row_is_the_unfunded_one_on_the_wire() {
        // Named apart from the `advert()` helper deliberately: the two sides of
        // this comparison are built by two independent calls to it, so the
        // assertion below is that the funded and unfunded paths agree on the
        // wire — not that one value equals itself.
        let advertisement = advert();
        let len = advertisement
            .encoded_len()
            .expect("a control advertisement counts");
        let encoded = advertisement
            .encode_exact(len)
            .expect("and encodes to that size");
        let device_id = "abcdefgh";
        let suffix_bytes = crate::identity::display_suffix_bytes(device_id.as_bytes());

        let unfunded = crate::handle::PeerInfo {
            device_id: device_id.to_string(),
            status: PeerStatus::Active,
            tier: ConnectionTier::Steady,
            rtt_ms: Some(17),
            clock_skew_ms: Some(-3),
            label: "Studio".to_string(),
            capabilities: Some(advert()),
            local_shelved: false,
            remote_shelved: true,
            authenticated: true,
            device_suffix: crate::identity::display_suffix(device_id.as_bytes()),
            verification_code_received: Some("13579".to_string()),
            verification_code_sent: None,
            local_approve_sent: true,
            remote_approve_seen: false,
            needs_turn: true,
            local_candidates: IceCandidateStats::default(),
            remote_candidates: IceCandidateStats::default(),
            selected_pair: None,
        };
        let funded = PublishedPeer {
            device_id: Box::from(device_id),
            status: PeerStatus::Active,
            tier: ConnectionTier::Steady,
            rtt_ms: Some(17),
            clock_skew_ms: Some(-3),
            label: Box::from("Studio"),
            capabilities: Some(
                validated_raw_advert(Box::from(&encoded[..])).expect("canonical bytes"),
            ),
            local_shelved: false,
            remote_shelved: true,
            authenticated: true,
            device_suffix: DisplaySuffix(suffix_bytes),
            verification_code_received: Some(Box::from("13579")),
            verification_code_sent: None,
            local_approve_sent: true,
            remote_approve_seen: false,
            needs_turn: true,
            local_candidates: IceCandidateStats::default(),
            remote_candidates: IceCandidateStats::default(),
            selected_pair: None,
        };

        assert_eq!(
            serde_json::to_string(&funded).expect("a published row serializes"),
            serde_json::to_string(&unfunded).expect("a peer info serializes"),
            "the raw carrier and the inline suffix are representation choices, \
             not wire ones"
        );
        // And the array framing too, which is what `commit` actually encodes:
        // the line must equal what `JoinedNetwork::peers` would serialize to.
        assert_eq!(
            encode_line_exact(
                std::slice::from_ref(&funded),
                encoded_line_len(std::slice::from_ref(&funded)).expect("a row counts"),
            )
            .expect("and encodes to that count")
            .as_ref(),
            serde_json::to_vec(std::slice::from_ref(&unfunded))
                .expect("a peer info list serializes")
                .as_slice(),
            "the published line is the peers array, byte for byte"
        );

        // The absent advertisement is the arm a `skip_serializing_if` would
        // quietly change, so it gets its own comparison rather than riding on
        // the one above.
        let mut unfunded_absent = unfunded;
        unfunded_absent.capabilities = None;
        let mut funded_absent = funded;
        funded_absent.capabilities = None;
        let absent = serde_json::to_string(&funded_absent).expect("a published row serializes");
        assert_eq!(
            absent,
            serde_json::to_string(&unfunded_absent).expect("a peer info serializes"),
        );
        assert!(
            absent.contains("\"capabilities\":null"),
            "an absent advertisement is published as null, not omitted"
        );
    }

    #[test]
    fn v4_r3_core_f7_the_row_ceiling_covers_the_widest_fixed_row() {
        // Every non-string field at its widest: the longest status and tier
        // tags, `false` rather than `true` on every bool, saturated candidate
        // counters, the extreme skew and round-trip, and a present selected
        // pair. Every string field at its narrowest, because the ceiling adds
        // those terms separately.
        let widest = PublishedPeer {
            device_id: Box::from(""),
            status: PeerStatus::PendingApproval,
            tier: ConnectionTier::IceWatchdog {
                since: std::time::Instant::now(),
            },
            rtt_ms: Some(u32::MAX),
            clock_skew_ms: Some(i64::MIN),
            label: Box::from(""),
            capabilities: None,
            local_shelved: false,
            remote_shelved: false,
            authenticated: false,
            device_suffix: DisplaySuffix([b'F'; DISPLAY_SUFFIX_CHARS]),
            verification_code_received: None,
            verification_code_sent: None,
            local_approve_sent: false,
            remote_approve_seen: false,
            needs_turn: false,
            local_candidates: IceCandidateStats {
                host: u32::MAX,
                server_reflexive: u32::MAX,
                peer_reflexive: u32::MAX,
                relay: u32::MAX,
                unknown: u32::MAX,
            },
            remote_candidates: IceCandidateStats {
                host: u32::MAX,
                server_reflexive: u32::MAX,
                peer_reflexive: u32::MAX,
                relay: u32::MAX,
                unknown: u32::MAX,
            },
            selected_pair: Some(SelectedCandidatePair {
                local: crate::transport::IceCandidateKind::ServerReflexive,
                remote: crate::transport::IceCandidateKind::ServerReflexive,
            }),
        };
        let measured = serde_json::to_string(&widest).expect("the widest fixed row serializes");
        assert!(
            measured.len() <= PEER_ROW_FIXED_CEILING,
            "the fixed ceiling must cover the widest fixed row, which measured \
             {} bytes against a ceiling of {PEER_ROW_FIXED_CEILING}",
            measured.len()
        );

        // And the composed ceiling covers a row with real strings in it. The
        // lengths below are what `PeerRowLengths::measure` would have recorded
        // for this row.
        let escaping = "\u{1}\u{2}\"\\\u{7f}";
        let awkward = PublishedPeer {
            device_id: Box::from(escaping),
            label: Box::from(escaping),
            verification_code_received: Some(Box::from(escaping)),
            ..widest
        };
        let lengths = PeerRowLengths {
            device_id: escaping.len(),
            label: escaping.len(),
            verification_code_received: Some(escaping.len()),
            verification_code_sent: None,
            capabilities: None,
        };
        let encoded = serde_json::to_string(&awkward).expect("an awkward row serializes");
        assert!(
            encoded.len() > measured.len(),
            "non-vacuity: those characters really do expand under escaping"
        );
        assert!(
            encoded.len()
                <= lengths
                    .encoded_ceiling()
                    .expect("the ceiling is representable"),
            "the composed ceiling covers a row whose every string needs escaping"
        );
    }

    #[test]
    fn v4_r3_core_f7_a_line_wider_than_admitted_is_refused_before_publication() {
        let (provider, port, scope) = ledger();
        let registry = PeerRegistry::default();
        let _ = registry.install(peer_with("alpha", "Alpha", None));
        let baseline = provider.in_use();

        let staging = PeerSnapshotStaging::new(&registry);
        let membership = acquire(
            &port,
            &scope,
            staging.membership_claim().expect("a one-peer roster plans"),
        );
        let prepared = staging.stage(membership).expect("the planned lease stages");

        // Fund everything the plan quoted, then narrow the line admission to a
        // width the built row cannot fit. This is the drift the seam exists for,
        // forced rather than waited for: real drift needs a row that retains the
        // same bytes and encodes wider, and the point of the gate is that it
        // does not matter *how* the two measurements came apart.
        let work = acquire(&port, &scope, prepared.work_claim());
        let typed = acquire(&port, &scope, prepared.typed_retention_claim());
        let output = acquire(&port, &scope, prepared.output_retention_claim());
        let narrowed = ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 1);
        let mut narrow_plan = prepared;
        narrow_plan.line_ceiling = 1;
        narrow_plan.line = narrowed;
        let line = acquire(&port, &scope, narrowed);

        match narrow_plan.commit(work, typed, output, line) {
            Ok(_snapshot) => panic!("a line wider than the admission must refuse"),
            Err(refusal) => assert_eq!(refusal, PeerSnapshotRefusal::LineWiderThanAdmitted),
        }
        assert_eq!(
            provider.in_use(),
            baseline,
            "the rows were built and then handed back — refusal releases every \
             lease, including the line admission that was too small"
        );
    }
}
