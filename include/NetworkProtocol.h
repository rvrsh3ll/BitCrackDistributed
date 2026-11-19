#pragma once

#include <algorithm>
#include <cctype>
#include <iterator>
#include <string>

enum class MessageVerb {
    Ping,
    Pong,
    Target,
    TargetBinary,
    KeyShare,
    Proposal,
    Vote,
    RewardAddress,      // Peer announces their reward address
    KeyFound,           // Peer found the solution key
    PayoutNotification, // Coordinator broadcasts payout details
    PuzzleAdvance,      // Coordinator signals puzzle progression
    PeerAddr,           // Peer gossip: share known peer endpoints and reward identities
    ContribUpdate,      // Peer broadcasts contribution delta (peer|keys|chunks)
    ContribSnapshot,    // Peer sends a full snapshot of contributions (peer|keys|chunks)
    ChunkDone,          // Peer broadcasts confirmed chunk completion (chunk_id|start|end|peer)
    ProgressBroadcast,  // P2P: Node broadcasts progress updates (keys_processed|current_range|timestamp)
    ValidationRequest,  // P2P: Request validation of a range (range_id|start|end|proof)
    ConsensusVote,      // P2P: Vote on range validation dispute (range_id|vote|signature)
    RangeClaim,         // P2P: Node claims a keyspace range (range_id|start|end|node_id)
        ChunkClaimProposal, // P2P: Node proposes to claim a chunk (chunk_id|start|end|node_id)
        ChunkClaimVote,     // P2P: Vote on chunk claim proposal (chunk_id|node_id|vote)
        ChunkClaimApproved, // P2P: Chunk claim approved by consensus (chunk_id|start|end|node_id)
    InventoryAnnounce,  // P2P: Announce inventory hashes (blocks)
    GetBlocks,          // P2P: Request block headers from a locator list
    Headers,            // P2P: Respond with block headers
    GetData,            // P2P: Request full block data
    Block,              // P2P: Broadcast a mined block
    BlockAnnounce,      // P2P: Announce a new block header (independent-node mode)
    BlockRequest,       // P2P: Request block by id/hash (independent-node mode)
    BlockData,          // P2P: Full block transmission (independent-node mode)
    GenesisBlock,       // P2P: Share genesis block for synchronization (height|previous_hash|merkle_root|timestamp|bits|nonce)
    GenesisAck,         // P2P: Acknowledge genesis block acceptance (genesis_hash)
    Commit,             // P2P: Announce a commitment (range_id|start|end|keys|proof)
    // Key-claim and MPC verbs
    KeyClaimRequest,    // Request to claim a puzzle key (finder|reward_addr)
    KeyClaimChallenge,  // Nonce + utxo to prove ownership (nonce|utxo|deadline)
    KeyProof,           // Finder proves key ownership (pubkey|sig)
    PsbtProposal,       // Coordinator/aggregator proposes PSBT for payout
    PartialSignature,   // A participant provides a partial signature on the PSBT
    AggregatedSignature,// Aggregated signature for PSBT (finalized)
    SignedTx,           // Final signed transaction hex
    KeyReveal,          // Optional: reveal private key after payout confirmation
    Unknown
};

inline std::string verbToString(MessageVerb verb) {
    switch (verb) {
        case MessageVerb::Ping: return "PING";
        case MessageVerb::Pong: return "PONG";
        case MessageVerb::Target: return "TARGET";
        case MessageVerb::TargetBinary: return "TARGETBIN";
        case MessageVerb::KeyShare: return "KEY";
        case MessageVerb::Proposal: return "PROPOSAL";
        case MessageVerb::Vote: return "VOTE";
        case MessageVerb::RewardAddress: return "REWARDADDR";
        case MessageVerb::KeyFound: return "KEYFOUND";
        case MessageVerb::PayoutNotification: return "PAYOUT";
        case MessageVerb::PuzzleAdvance: return "PUZZLEADV";
        case MessageVerb::PeerAddr: return "PEERADDR";
        case MessageVerb::ContribUpdate: return "CONTRIB";
        case MessageVerb::ContribSnapshot: return "CONTRIBSNAP";
        case MessageVerb::ChunkDone: return "CHUNKDONE";
        case MessageVerb::ProgressBroadcast: return "PROGRESSBROADCAST";
        case MessageVerb::ValidationRequest: return "VALIDATIONREQUEST";
        case MessageVerb::ConsensusVote: return "CONSENSUSVOTE";
        case MessageVerb::RangeClaim: return "RANGECLAIM";
            case MessageVerb::ChunkClaimProposal: return "CHUNKCLAIMPROPOSAL";
            case MessageVerb::ChunkClaimVote: return "CHUNKCLAIMVOTE";
            case MessageVerb::ChunkClaimApproved: return "CHUNKCLAIMAPPROVED";
        case MessageVerb::InventoryAnnounce: return "INV";
        case MessageVerb::GetBlocks: return "GETBLOCKS";
        case MessageVerb::Headers: return "HEADERS";
        case MessageVerb::GetData: return "GETDATA";
        case MessageVerb::Block: return "BLOCK";
        case MessageVerb::BlockAnnounce: return "BLOCKANN";
        case MessageVerb::BlockRequest: return "BLOCKREQ";
        case MessageVerb::BlockData: return "BLOCKDATA";
        case MessageVerb::GenesisBlock: return "GENESISBLOCK";
        case MessageVerb::GenesisAck: return "GENESISACK";
        case MessageVerb::Commit: return "COMMIT";
            case MessageVerb::KeyClaimRequest: return "KEYCLAIMREQ";
            case MessageVerb::KeyClaimChallenge: return "KEYCLAIMCHALLENGE";
            case MessageVerb::KeyProof: return "KEYPROOF";
            case MessageVerb::PsbtProposal: return "PSBTPROPOSAL";
            case MessageVerb::PartialSignature: return "PARTIALSIGNATURE";
            case MessageVerb::AggregatedSignature: return "AGGREGATEDSIGNATURE";
            case MessageVerb::SignedTx: return "SIGNEDTX";
            case MessageVerb::KeyReveal: return "KEYREVEAL";
        default: return "UNKNOWN";
    }
}

inline MessageVerb parseVerb(const std::string& token) {
    std::string normalized;
    normalized.reserve(token.size());
    std::transform(token.begin(), token.end(), std::back_inserter(normalized), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });

    if (normalized == "PING") return MessageVerb::Ping;
    if (normalized == "PONG") return MessageVerb::Pong;
    if (normalized == "TARGET") return MessageVerb::Target;
    if (normalized == "TARGETBIN") return MessageVerb::TargetBinary;
    if (normalized == "KEY") return MessageVerb::KeyShare;
    if (normalized == "PROPOSAL") return MessageVerb::Proposal;
    if (normalized == "VOTE") return MessageVerb::Vote;
    if (normalized == "REWARDADDR") return MessageVerb::RewardAddress;
    if (normalized == "KEYFOUND") return MessageVerb::KeyFound;
    if (normalized == "PAYOUT") return MessageVerb::PayoutNotification;
    if (normalized == "PUZZLEADV") return MessageVerb::PuzzleAdvance;
    if (normalized == "PEERADDR") return MessageVerb::PeerAddr;
    if (normalized == "CONTRIB") return MessageVerb::ContribUpdate;
    if (normalized == "CONTRIBSNAP") return MessageVerb::ContribSnapshot;
    if (normalized == "CHUNKDONE") return MessageVerb::ChunkDone;
    if (normalized == "PROGRESSBROADCAST") return MessageVerb::ProgressBroadcast;
    if (normalized == "VALIDATIONREQUEST") return MessageVerb::ValidationRequest;
    if (normalized == "CONSENSUSVOTE") return MessageVerb::ConsensusVote;
    if (normalized == "RANGECLAIM") return MessageVerb::RangeClaim;
        if (normalized == "CHUNKCLAIMPROPOSAL") return MessageVerb::ChunkClaimProposal;
        if (normalized == "CHUNKCLAIMVOTE") return MessageVerb::ChunkClaimVote;
        if (normalized == "CHUNKCLAIMAPPROVED") return MessageVerb::ChunkClaimApproved;
    if (normalized == "INV") return MessageVerb::InventoryAnnounce;
    if (normalized == "GETBLOCKS") return MessageVerb::GetBlocks;
    if (normalized == "HEADERS") return MessageVerb::Headers;
    if (normalized == "GETDATA") return MessageVerb::GetData;
    if (normalized == "BLOCK") return MessageVerb::Block;
    if (normalized == "BLOCKANN") return MessageVerb::BlockAnnounce;
    if (normalized == "BLOCKREQ") return MessageVerb::BlockRequest;
    if (normalized == "BLOCKDATA") return MessageVerb::BlockData;
    if (normalized == "GENESISBLOCK") return MessageVerb::GenesisBlock;
    if (normalized == "GENESISACK") return MessageVerb::GenesisAck;
    if (normalized == "COMMIT") return MessageVerb::Commit;
    if (normalized == "KEYCLAIMREQ") return MessageVerb::KeyClaimRequest;
    if (normalized == "KEYCLAIMCHALLENGE") return MessageVerb::KeyClaimChallenge;
    if (normalized == "KEYPROOF") return MessageVerb::KeyProof;
    if (normalized == "PSBTPROPOSAL") return MessageVerb::PsbtProposal;
    if (normalized == "PARTIALSIGNATURE") return MessageVerb::PartialSignature;
    if (normalized == "AGGREGATEDSIGNATURE") return MessageVerb::AggregatedSignature;
    if (normalized == "SIGNEDTX") return MessageVerb::SignedTx;
    if (normalized == "KEYREVEAL") return MessageVerb::KeyReveal;
    return MessageVerb::Unknown;
}
