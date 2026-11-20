#pragma once
// Chunk-claim voting state (refactor step 4).
//
// The claim data types, pure helpers and state containers moved out
// of NetworkManager unchanged. ClaimBook is not thread-safe: its owner
// guards all of it with one mutex (NetworkManager::chunk_claim_mutex_).
// No behaviour, log or wire change.
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace chunk_claim {

using Clock = std::chrono::steady_clock;

// DOS protection: max active (pending + claimed) chunks per node.
inline constexpr int kMaxChunksPerPeer = 2;
// A vote that arrived before its proposal is kept this long.
inline constexpr int kBufferedVoteTimeoutSec = 30;

// A proposal being voted on.
struct Proposal {
    std::string chunk_id;
    std::string start_key;
    std::string end_key;
    std::string proposer_id;
    std::unordered_set<std::string> approvals;
    std::unordered_set<std::string> rejections;
    Clock::time_point proposed_at;
    bool finalized = false;
    bool approved = false;
};

// A lease on an approved claim held by another node. A holder's
// CHUNKDONE renews its leases.
struct Lease {
    std::string chunk_id;
    std::string start_key;
    std::string end_key;
    std::string holder;
    Clock::time_point approved_at;
};

// A vote received before its proposal.
struct BufferedVote {
    std::string chunk_id;
    std::string peer_alias;
    std::string proposer_id;
    std::string vote;
    Clock::time_point received_at;
};

// A finalized claim, to publish after releasing the claim mutex.
struct Outcome {
    bool finalized = false;
    bool approved = false;
    std::string chunk_id, proposer_id, start_key, end_key;
};

using Range = std::pair<std::string, std::string>;  // (start, end)

// Claim state key: chunk ids are per-node counters and collide
// across nodes, so a claim is identified by (chunk_id, proposer).
std::string claimKey(const std::string& chunk_id, const std::string& proposer_id);

// Inclusive hex ranges [a_start, a_end] and [b_start, b_end] overlap.
bool rangesOverlap(const std::string& a_start, const std::string& a_end, const std::string& b_start,
                   const std::string& b_end);

// Decrements counts[alias], never below zero (the entry is removed at 0).
void decrementCount(std::unordered_map<std::string, int>& counts, const std::string& alias);

// All chunk-claim voting state.
struct ClaimBook {
    std::unordered_map<std::string, Proposal> pending;  // claimKey -> proposal
    std::unordered_map<std::string, Range> claimed;     // claimKey -> approved range
    std::unordered_map<std::string, Range> rejected;    // claimKey -> range, for claims rejected or replaced
    std::unordered_map<std::string, int> pending_count;  // peer alias -> pending proposals
    std::unordered_map<std::string, int> claimed_count;  // peer alias -> claimed chunks
    std::unordered_map<std::string, Lease> leases;                       // claimKey -> lease
    std::unordered_map<std::string, Clock::time_point> holder_last_done;  // holder -> last CHUNKDONE
    std::unordered_map<std::string, double> holder_min_rate;             // holder -> slowest keys/s seen
    std::deque<BufferedVote> buffered_votes;  // votes received before their proposal
    Clock::time_point last_claim_attempt{};
    bool timeout_extended = false;  // extend the next proposal-expiry check once (buffered votes)

    // The decisions of proposing, voting and tallying. The caller
    // holds the claim mutex; side effects (broadcasts, coordinator, engine,
    // strikes) stay with it. Log lines are unchanged.

    // Voters right now (handshaken peers + ourselves); asked while tallying.
    using VoterCount = std::function<size_t()>;

    // Records our own proposal (with our own approval); false, and logged,
    // if one is already pending under the same key.
    bool addOwnProposal(const std::string& chunk_id, const std::string& start_key, const std::string& end_key,
                        const std::string& local_alias);

    // How a peer's CHUNKCLAIMPROPOSAL was decided (state already updated).
    struct ProposalDecision {
        bool duplicate = false;       // already seen: ignore, no vote
        bool should_approve = true;   // our vote
        bool too_many = false;        // per-peer limit hit (strike the proposer)
        std::string too_many_detail;
        std::vector<std::string> dropped_own;  // our chunk ids whose claims lost
        // Remote proposals replaced by this one: (start, end, proposer).
        std::vector<std::tuple<std::string, std::string, std::string>> replaced_remote;
        std::vector<Outcome> replayed;  // claims finalized by buffered votes
    };
    ProposalDecision evaluateProposal(const std::string& chunk_id, const std::string& start_key,
                                      const std::string& end_key, const std::string& proposer_id,
                                      const VoterCount& voter_count, const std::string& local_alias);

    // Counts a vote (or buffers it if its proposal is unknown); returns the
    // outcome if the vote finalized the claim.
    Outcome recordVote(const std::string& chunk_id, const std::string& proposer_id, const std::string& peer_alias,
                       const std::string& vote, const VoterCount& voter_count, const std::string& local_alias);

    // Finalizes `it` if the votes decide it (erasing it from pending).
    Outcome tally(std::unordered_map<std::string, Proposal>::iterator it, const VoterCount& voter_count,
                  const std::string& local_alias);

    // Replays buffered votes whose proposal now exists; returns the claims
    // they finalized.
    std::vector<Outcome> reprocessBufferedVotes(const VoterCount& voter_count, const std::string& local_alias);

    // Leases another node's approved claim (first approval wins).
    void addLease(const std::string& key, const std::string& chunk_id, const std::string& start_key,
                  const std::string& end_key, const std::string& holder, const std::string& local_alias);

    // Expiry, leases and peer loss (caller holds the claim mutex).

    // An unfinalized proposal of ours is pending.
    bool hasLiveOwnProposal(const std::string& local_alias) const;
    // Claimed by any proposer.
    bool isClaimed(const std::string& chunk_id) const;
    // Drops a lost peer's claims, proposals, counters and leases.
    void forgetPeer(const std::string& alias);
    // A holder completed [start_key, end_key] at `now`: renews its leases,
    // records its rate and drops the lease on that range.
    void noteHolderCompletion(const std::string& holder, const std::string& start_key, const std::string& end_key,
                              Clock::time_point now);
    // Lease length for `lease`: factor x the expected time at the holder's
    // slowest seen rate (or the slowest holder's), at least min_s.
    uint64_t leaseSeconds(const Lease& lease, uint64_t min_s, uint64_t factor) const;

    // Leases that ran out at `now` (their claims are dropped here).
    struct ExpiredLease {
        Lease lease;
        uint64_t lease_s;
        long long idle_s;
    };
    using RangeRetired = std::function<bool(const std::string& start, const std::string& end)>;
    std::vector<ExpiredLease> takeExpiredLeases(Clock::time_point now, uint64_t min_s, uint64_t factor,
                                                const RangeRetired& is_retired);

    // Pending proposals older than the timeout at `now`, removed from
    // pending: (chunk_id, proposer_id, age_seconds, key, start, end).
    using ExpiredProposal = std::tuple<std::string, std::string, long long, std::string, std::string, std::string>;
    std::vector<ExpiredProposal> takeExpiredProposals(uint32_t timeout, Clock::time_point now);

    // The claim throttle and the per-proposer claimed check.

    // Records a claim attempt at `now` unless the last one was less than
    // `min_interval` ago (then false, nothing recorded).
    bool startAttempt(Clock::time_point now, std::chrono::milliseconds min_interval);
    // Time until the next attempt is allowed (0 if allowed now); rounded up
    // by 1 ms so a caller sleeping that long is past the throttle.
    std::chrono::milliseconds throttleRemaining(Clock::time_point now, std::chrono::milliseconds min_interval) const;
    // Claimed by exactly this proposer.
    bool isClaimedBy(const std::string& chunk_id, const std::string& proposer_id) const;
};

}  // namespace chunk_claim
