#include "ChunkClaimBook.h"

#include <algorithm>
#include <cstdint>
#include <iterator>

#include "HexMath.h"
#include "Logger.h"
#include "WireCodec.h"

namespace chunk_claim {

std::string claimKey(const std::string& chunk_id, const std::string& proposer_id) {
    return chunk_id + "|" + proposer_id;
}

bool rangesOverlap(const std::string& a_start, const std::string& a_end, const std::string& b_start,
                   const std::string& b_end) {
    return HexMath::compare(a_start, b_end) <= 0 && HexMath::compare(b_start, a_end) <= 0;
}

void decrementCount(std::unordered_map<std::string, int>& counts, const std::string& alias) {
    // Never below zero: a stray or duplicate decrement used to drive a
    // counter negative.
    auto it = counts.find(alias);
    if (it == counts.end()) return;
    if (--it->second <= 0) counts.erase(it);
}

// The decision parts of proposing, voting and tallying, moved from
// NetworkManager unchanged (same log lines). The caller holds the claim mutex.

bool ClaimBook::addOwnProposal(const std::string& chunk_id, const std::string& start_key, const std::string& end_key,
                               const std::string& local_alias) {
    const std::string key = claimKey(chunk_id, local_alias);

    if (pending.count(key) > 0) {
        Logger::debug("Chunk claim already pending: " + chunk_id);
        return false;
    }

    Proposal proposal;
    proposal.chunk_id = chunk_id;
    proposal.start_key = start_key;
    proposal.end_key = end_key;
    proposal.proposer_id = local_alias;
    proposal.proposed_at = Clock::now();
    proposal.finalized = false;
    proposal.approved = false;
    proposal.approvals.insert(local_alias);

    pending[key] = proposal;
    // A fresh proposal under a reused key starts with a clean slate.
    rejected.erase(key);
    claimed.erase(key);
    return true;
}

ClaimBook::ProposalDecision ClaimBook::evaluateProposal(const std::string& chunk_id, const std::string& start_key,
                                                        const std::string& end_key, const std::string& proposer_id,
                                                        const VoterCount& voter_count,
                                                        const std::string& local_alias) {
    bool should_approve = true;
    bool too_many = false;
    std::string too_many_detail;

    const std::string key = claimKey(chunk_id, proposer_id);
    bool duplicate = false;
    std::vector<std::string> dropped_own;  // our chunk ids whose claims lost
    std::vector<Outcome> replayed;  // claims finalized by buffered votes
    // Remote proposals replaced by this one: (start, end, proposer).
    std::vector<std::tuple<std::string, std::string, std::string>> replaced_remote;
    // The same proposal arrives once per connection. Count and
    // vote on it once; a second pass used to double-increment
    // pending_count and could flip an approval into a reject.
    // A key with a different range is a fresh proposal under a reused
    // id (the proposer restarted and its counter began again).
    auto same = pending.find(key);
    if (same != pending.end()) {
        if (same->second.start_key == start_key && same->second.end_key == end_key) {
            duplicate = true;
        } else {
            decrementCount(pending_count, proposer_id);
            pending.erase(same);
        }
    }
    auto done = claimed.find(key);
    if (done != claimed.end() && done->second.first == start_key && done->second.second == end_key) {
        duplicate = true;
    }
    auto rej = rejected.find(key);
    if (rej != rejected.end()) {
        if (rej->second.first == start_key && rej->second.second == end_key) {
            duplicate = true;  // already voted REJECT on this one
        } else {
            rejected.erase(rej);
        }
    }

    // DOS protection: reject if peer already has too many active
    // chunks. Checked after the duplicate test: a second copy of an
    // approved proposal used to count against (and strike) the peer.
    if (!duplicate) {
        const int pending = pending_count.count(proposer_id) ? pending_count[proposer_id] : 0;
        const int claimed = claimed_count.count(proposer_id) ? claimed_count[proposer_id] : 0;
        if (pending + claimed >= kMaxChunksPerPeer) {
            should_approve = false;
            too_many = true;
            too_many_detail = std::to_string(pending) + " pending + " + std::to_string(claimed) + " claimed";
        }
    }

    if (!duplicate && should_approve) {
        // Conflicts are decided by range overlap, not chunk id.
        // Chunk ids are per-node counters, so two nodes routinely
        // propose different ranges under the same id.
        for (const auto& kv : claimed) {
            if (rangesOverlap(start_key, end_key, kv.second.first, kv.second.second)) {
                should_approve = false;
                Logger::debug("Rejecting claim " + chunk_id + " from " + proposer_id +
                              ": overlaps claimed range " + kv.second.first + "-" + kv.second.second);
                break;
            }
        }
    }

    if (!duplicate && should_approve) {
        // Overlapping pending proposals from other proposers: the
        // lexically smallest proposer wins (same rule as before).
        std::vector<std::string> losers;
        for (const auto& kv : pending) {
            const auto& p = kv.second;
            if (p.proposer_id == proposer_id || p.finalized) continue;
            if (!rangesOverlap(start_key, end_key, p.start_key, p.end_key)) continue;
            if (p.proposer_id < proposer_id) {
                should_approve = false;
                Logger::debug("Rejecting claim " + chunk_id + " from " + proposer_id +
                              ": overlaps higher-priority proposal " + p.chunk_id + " from " + p.proposer_id);
                break;
            }
            losers.push_back(kv.first);
        }
        if (should_approve) {
            for (const auto& lk_key : losers) {
                auto it = pending.find(lk_key);
                if (it == pending.end()) continue;
                const auto& p = it->second;
                Logger::info("Replacing chunk proposal " + p.chunk_id + " from " + p.proposer_id +
                             " with overlapping " + chunk_id + " from " + proposer_id);
                if (p.proposer_id == local_alias) {
                    dropped_own.push_back(p.chunk_id);
                } else {
                    decrementCount(pending_count, p.proposer_id);
                    replaced_remote.emplace_back(p.start_key, p.end_key, p.proposer_id);
                }
                rejected[lk_key] = {p.start_key, p.end_key};
                pending.erase(it);
            }
        }
    }

    if (!duplicate && !should_approve) {
        rejected[key] = {start_key, end_key};
    }

    if (!duplicate && should_approve) {
        Proposal& proposal = pending[key];
        proposal.chunk_id = chunk_id;
        proposal.start_key = start_key;
        proposal.end_key = end_key;
        proposal.proposer_id = proposer_id;
        if (proposal.proposed_at.time_since_epoch().count() == 0) {
            proposal.proposed_at = Clock::now();
        }
        pending_count[proposer_id]++;  // Track new pending claim
        
        // Reprocess buffered votes that were waiting for this proposal to arrive
        replayed = reprocessBufferedVotes(voter_count, local_alias);
    }

    ProposalDecision d;
    d.duplicate = duplicate;
    d.should_approve = should_approve;
    d.too_many = too_many;
    d.too_many_detail = std::move(too_many_detail);
    d.dropped_own = std::move(dropped_own);
    d.replaced_remote = std::move(replaced_remote);
    d.replayed = std::move(replayed);
    return d;
}

Outcome ClaimBook::recordVote(const std::string& chunk_id, const std::string& proposer_id, const std::string& peer_alias,
                              const std::string& vote, const VoterCount& voter_count,
                              const std::string& local_alias) {
    const std::string key = claimKey(chunk_id, proposer_id);
    // Skip votes for claims that were explicitly rejected or already claimed
    if (rejected.count(key) > 0 || claimed.count(key) > 0) {
        Logger::debug("Ignoring vote for rejected/claimed chunk: " + chunk_id);
        return Outcome{};
    }

    auto it = pending.find(key);
    if (it == pending.end()) {
        // Buffer vote if proposal not yet received (race condition: vote arrives before proposal)
        BufferedVote bv{chunk_id, peer_alias, proposer_id, vote, Clock::now()};
        buffered_votes.push_back(bv);
        Logger::debug("Buffered vote for unknown proposal (will reprocess): " + chunk_id + " from " + peer_alias);
        return Outcome{};
    }

    if (vote == wire::kVoteApprove) {
        it->second.approvals.insert(peer_alias);
    } else {
        it->second.rejections.insert(peer_alias);
    }
    return tally(it, voter_count, local_alias);
}

Outcome ClaimBook::tally(std::unordered_map<std::string, Proposal>::iterator it, const VoterCount& voter_count,
                         const std::string& local_alias) {
    // Caller holds the claim mutex. Shared by live votes and replayed
    // buffered votes, so both finalize a claim the same way.
    Outcome out;
    const std::string key = it->first;
    auto& proposal = it->second;
    const std::string& chunk_id = proposal.chunk_id;
    const std::string proposer_id = proposal.proposer_id;

    // Voters: handshaken peers (distinct aliases) + ourselves.
    const size_t total_peers = voter_count();

    // For 2 nodes, require both to approve (simple majority)
    size_t min_approvals = (total_peers / 2) + 1;
    Logger::debug("Chunk claim vote tally: " + chunk_id + " approvals=" + std::to_string(proposal.approvals.size()) + 
                  " rejections=" + std::to_string(proposal.rejections.size()) + 
                  " total_peers=" + std::to_string(total_peers) + 
                  " min_approvals=" + std::to_string(min_approvals));

    if (proposal.approvals.size() >= min_approvals) {
        proposal.finalized = true;
        proposal.approved = true;
        claimed[key] = {proposal.start_key, proposal.end_key};
        addLease(key, chunk_id, proposal.start_key, proposal.end_key, proposer_id, local_alias);
        out = Outcome{true, true, chunk_id, proposer_id, proposal.start_key, proposal.end_key};
        pending.erase(it);
        // Transfer from pending to claimed counts
        decrementCount(pending_count, proposer_id);
        claimed_count[proposer_id]++;
        // Clear from rejected set now that it's approved
        rejected.erase(key);
        
        // Extend consensus timeout by 10 seconds when buffered votes are reprocessed for recovery
        timeout_extended = true;
    } else if (proposal.rejections.size() > (total_peers / 2) ||
               // Also finalize once the outstanding votes can no
               // longer reach min_approvals (with 2 nodes one REJECT
               // decides it). The claim used to sit pending until expiry,
               // blocking the idle retry.
               proposal.approvals.size() +
                       (total_peers > proposal.approvals.size() + proposal.rejections.size()
                            ? total_peers - proposal.approvals.size() - proposal.rejections.size()
                            : 0) <
                   min_approvals) {
        proposal.finalized = true;
        proposal.approved = false;
        out = Outcome{true, false, chunk_id, proposer_id, proposal.start_key, proposal.end_key};
        rejected[key] = {proposal.start_key, proposal.end_key};
        pending.erase(it);
        // Release pending count on rejection
        decrementCount(pending_count, proposer_id);
    }
    return out;
}

std::vector<Outcome> ClaimBook::reprocessBufferedVotes(const VoterCount& voter_count, const std::string& local_alias) {
    std::vector<Outcome> outcomes;
    // Called while holding the claim mutex
    // Reprocess any buffered votes that were waiting for proposals to arrive
    auto now = Clock::now();
    std::vector<BufferedVote> to_reprocess;
    
    // Find all buffered votes that now have matching proposals
    std::deque<BufferedVote> remaining;
    for (const auto& bv : buffered_votes) {
        // Skip votes for rejected or already claimed chunks
        const std::string bv_key = claimKey(bv.chunk_id, bv.proposer_id);
        if (rejected.count(bv_key) > 0 || claimed.count(bv_key) > 0) {
            Logger::debug("Discarding buffered vote for rejected/claimed chunk: " + bv.chunk_id);
            continue;
        }
        
        auto age_sec = std::chrono::duration_cast<std::chrono::seconds>(now - bv.received_at).count();
        if (age_sec > kBufferedVoteTimeoutSec) {
            // Vote expired, discard it
            Logger::debug("Discarding expired buffered vote for " + bv.chunk_id);
            continue;
        }
        
        auto it = pending.find(bv_key);
        if (it != pending.end()) {
            // Proposal now exists with matching proposer, reprocess this vote
            to_reprocess.push_back(bv);
        } else {
            // Keep buffering this vote
            remaining.push_back(bv);
        }
    }
    buffered_votes = remaining;
    
    // Now process the votes (unlock not needed here since we hold the lock)
    for (const auto& bv : to_reprocess) {
        auto it = pending.find(claimKey(bv.chunk_id, bv.proposer_id));
        if (it == pending.end()) continue;
        
        auto& proposal = it->second;
        Logger::debug("Reprocessing buffered vote for " + bv.chunk_id + " from " + bv.peer_alias);
        
        if (bv.vote == wire::kVoteApprove) {
            proposal.approvals.insert(bv.peer_alias);
        } else {
            proposal.rejections.insert(bv.peer_alias);
        }
        
        // Finalize exactly like a live vote. The replay used to
        // mark the claim approved but leave it pending (never expired,
        // pending_count never released, so the peer hit the
        // per-peer limit) and never broadcast or applied the approval.
        Outcome o = tally(it, voter_count, local_alias);  // erases it when finalized
        if (o.finalized) {
            Logger::info("Chunk claim " + std::string(o.approved ? "reached consensus" : "rejected") +
                         " after reprocessing buffered votes: " + bv.chunk_id);
            outcomes.push_back(std::move(o));
        }
    }
    return outcomes;
}

void ClaimBook::addLease(const std::string& key, const std::string& chunk_id, const std::string& start_key,
                         const std::string& end_key, const std::string& holder, const std::string& local_alias) {
    if (holder.empty() || holder == local_alias) return;  // our own claims are not leased
    if (leases.count(key)) return;                       // duplicate approval: keep the first time
    leases[key] = Lease{chunk_id, start_key, end_key, holder, Clock::now(), next_lease_seq++};
}

// The expiry, lease and peer-loss parts, moved from NetworkManager
// unchanged (same log lines). The caller holds the claim mutex.

bool ClaimBook::hasLiveOwnProposal(const std::string& local_alias) const {
    for (const auto& kv : pending) {
        if (!kv.second.finalized && kv.second.proposer_id == local_alias) return true;
    }
    return false;
}

bool ClaimBook::isClaimed(const std::string& chunk_id) const {
    // Claimed by any proposer.
    const std::string prefix = chunk_id + "|";
    for (const auto& kv : claimed) {
        if (kv.first.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}

void ClaimBook::forgetPeer(const std::string& alias) {
    const std::string suffix = "|" + alias;
    auto is_peers = [&](const std::string& k) {
        const auto bar = k.rfind('|');
        return bar != std::string::npos && k.compare(bar, std::string::npos, suffix) == 0;
    };
    for (auto it = claimed.begin(); it != claimed.end();) {
        it = is_peers(it->first) ? claimed.erase(it) : std::next(it);
    }
    for (auto it = pending.begin(); it != pending.end();) {
        it = it->second.proposer_id == alias ? pending.erase(it) : std::next(it);
    }
    claimed_count.erase(alias);
    pending_count.erase(alias);
    for (auto it = leases.begin(); it != leases.end();) {
        it = it->second.holder == alias ? leases.erase(it) : std::next(it);
    }
}

void ClaimBook::noteHolderCompletion(const std::string& holder, const std::string& start_key, const std::string& end_key,
                                     Clock::time_point now) {
    holder_last_done[holder] = now;
    // The holder's rate for this chunk, measured from the approval (an
    // underestimate if it was queued behind another chunk: generous).
    for (auto it = leases.begin(); it != leases.end();) {
        const Lease& l = it->second;
        if (l.holder == holder && l.start_key == start_key && l.end_key == end_key) {
            const double secs = std::chrono::duration<double>(now - l.approved_at).count();
            const std::string span = HexMath::add(HexMath::subtract(end_key, start_key), "1");
            if (secs >= 1.0 && HexMath::fitsU64(span)) {
                const double rate = static_cast<double>(std::stoull(span, nullptr, 16)) / secs;
                auto r = holder_min_rate.find(holder);
                if (r == holder_min_rate.end() || rate < r->second) holder_min_rate[holder] = rate;
            }
            it = leases.erase(it);
        } else {
            ++it;
        }
    }
}

bool ClaimBook::releaseClaim(const std::string& key, const std::string& holder) {
    leases.erase(key);
    if (claimed.erase(key) == 0) return false;
    decrementCount(claimed_count, holder);
    return true;
}

std::vector<Lease> ClaimBook::takeSupersededLeases(const std::string& holder, const std::string& start_key,
                                                   const std::string& end_key) {
    std::vector<Lease> superseded;
    if (holder.empty()) return superseded;
    const Lease* done = nullptr;
    for (const auto& kv : leases) {
        const Lease& l = kv.second;
        if (l.holder == holder && l.start_key == start_key && l.end_key == end_key) {
            done = &l;
            break;
        }
    }
    if (!done) return superseded;
    const uint64_t done_seq = done->seq;
    for (auto it = leases.begin(); it != leases.end();) {
        const Lease& l = it->second;
        if (l.holder != holder || l.seq >= done_seq) {
            ++it;
            continue;
        }
        superseded.push_back(l);
        if (claimed.erase(it->first) > 0) decrementCount(claimed_count, holder);
        it = leases.erase(it);
    }
    return superseded;
}

uint64_t ClaimBook::leaseSeconds(const Lease& lease, uint64_t min_s, uint64_t factor) const {
    double rate = 0.0;
    auto r = holder_min_rate.find(lease.holder);
    if (r != holder_min_rate.end()) {
        rate = r->second;
    } else {
        for (const auto& kv : holder_min_rate)  // no history: the slowest holder seen
            if (rate == 0.0 || kv.second < rate) rate = kv.second;
    }
    const std::string span = HexMath::add(HexMath::subtract(lease.end_key, lease.start_key), "1");
    if (rate <= 0.0 || !HexMath::fitsU64(span)) return min_s;
    const double expected = static_cast<double>(std::stoull(span, nullptr, 16)) / rate;
    const double lease_s = static_cast<double>(factor) * expected;
    if (lease_s >= 1e15) return UINT64_MAX / 2;
    return std::max<uint64_t>(min_s, static_cast<uint64_t>(lease_s));
}

std::vector<ClaimBook::ExpiredLease> ClaimBook::takeExpiredLeases(Clock::time_point now, uint64_t min_s, uint64_t factor,
                                                                  const RangeRetired& is_retired) {
    std::vector<ExpiredLease> expired;
    for (auto it = leases.begin(); it != leases.end();) {
        if (!claimed.count(it->first)) {  // claim gone (completed, holder dropped, ...)
            it = leases.erase(it);
            continue;
        }
        const Lease& l = it->second;
        if (is_retired(l.start_key, l.end_key)) {  // done (by anyone)
            it = leases.erase(it);
            continue;
        }
        auto since = l.approved_at;
        auto d = holder_last_done.find(l.holder);
        if (d != holder_last_done.end() && d->second > since) since = d->second;  // progress renews
        const long long idle = std::chrono::duration_cast<std::chrono::seconds>(now - since).count();
        const uint64_t lease_s = leaseSeconds(l, min_s, factor);
        if (idle < 0 || static_cast<uint64_t>(idle) <= lease_s) {
            ++it;
            continue;
        }
        expired.push_back({l, lease_s, idle});
        claimed.erase(it->first);
        decrementCount(claimed_count, l.holder);
        it = leases.erase(it);
    }
    return expired;
}

std::vector<ClaimBook::ExpiredProposal> ClaimBook::takeExpiredProposals(uint32_t timeout, Clock::time_point now) {
    std::vector<ExpiredProposal> expired;
    for (const auto& kv : pending) {
        const auto& proposal = kv.second;
        if (proposal.finalized) continue;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - proposal.proposed_at).count();
        
        // Extend timeout by 10 seconds if consensus was extended due to buffered vote reprocessing
        uint32_t effective_timeout = timeout;
        if (timeout_extended) {
            effective_timeout += 10;
            timeout_extended = false;  // Reset flag after one use
        }
        
        if (elapsed > static_cast<long long>(effective_timeout)) {
            expired.emplace_back(proposal.chunk_id, proposal.proposer_id, elapsed, kv.first,
                                 proposal.start_key, proposal.end_key);
        }
    }
    // Remove expired entries from pending map
    for (const auto& t : expired) {
        const auto& proposer = std::get<1>(t);
        pending.erase(std::get<3>(t));
        // Decrement pending count for the proposer
        auto pc_it = pending_count.find(proposer);
        if (pc_it != pending_count.end()) {
            pc_it->second--;
            if (pc_it->second <= 0) {
                pending_count.erase(pc_it);
            }
        }
    }
    return expired;
}

// Moved from NetworkManager::tryClaimNextChunk,
// claimThrottleRemaining and isChunkClaimedBy unchanged.

bool ClaimBook::startAttempt(Clock::time_point now, std::chrono::milliseconds min_interval) {
    if (last_claim_attempt.time_since_epoch().count() != 0 &&
        now - last_claim_attempt < min_interval) {
        return false;
    }
    last_claim_attempt = now;
    return true;
}

std::chrono::milliseconds ClaimBook::throttleRemaining(Clock::time_point now, std::chrono::milliseconds min_interval) const {
    if (last_claim_attempt.time_since_epoch().count() == 0) return std::chrono::milliseconds(0);
    const auto next = last_claim_attempt + min_interval;
    if (next <= now) return std::chrono::milliseconds(0);
    return std::chrono::duration_cast<std::chrono::milliseconds>(next - now) + std::chrono::milliseconds(1);
}

bool ClaimBook::isClaimedBy(const std::string& chunk_id, const std::string& proposer_id) const {
    return claimed.count(claimKey(chunk_id, proposer_id)) > 0;
}

}  // namespace chunk_claim
