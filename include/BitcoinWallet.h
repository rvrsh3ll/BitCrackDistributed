#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include "AddressGenerator.h"  // BitcoinNetwork

class ElectrumClient;

struct PayoutOutput {
    std::string address;
    uint64_t amount_satoshis;
    double percentage;
    std::string label;
};

class BitcoinWallet {
public:
    BitcoinWallet(const std::string& rpc_url = "", const std::string& user = "", const std::string& pass = "");
    ~BitcoinWallet();
    
    // Create a payout transaction that sweeps the puzzle wallet
    std::string createPayoutTransaction(
        const std::string& puzzle_address,
        const std::string& private_key,
        const std::vector<PayoutOutput>& outputs,
        // If given, receives the outputs the signed transaction pays
        // (after the fee and dust handling); empty on failure.
        std::vector<PayoutOutput>* paid_outputs = nullptr
    );

    struct Utxo {
        std::string txid;
        uint32_t vout;
        uint64_t value_satoshis;
    };
    std::vector<Utxo> listUnspentUTXOs(const std::string& address);
    // false if the lookup failed (no backend, node unreachable, RPC or
    // Electrum error), so a failure is not mistaken for an empty address.
    bool tryListUnspentUTXOs(const std::string& address, std::vector<Utxo>& out);
    // The fee the payout paths use for n_in inputs of in_spk's type
    // and n_out payee outputs (conservative: counts one change output).
    // with_change adds a change output to the estimate.
    static uint64_t estimatePayoutFee(size_t n_in, const std::vector<unsigned char>& in_spk, size_t n_out,
                                      bool with_change);
    std::string buildRawTransaction(const std::vector<Utxo>& utxos, const std::vector<PayoutOutput>& outputs, const std::vector<unsigned char>& scriptPubKey, uint64_t fee);
    std::string signRawTransaction(const std::string& raw_tx_hex, const std::vector<Utxo>& utxos, const std::vector<unsigned char>& scriptPubKey, const std::string& private_key_hex);
    
    // Broadcast transaction to network
    bool broadcastTransaction(const std::string& signed_tx_hex);
    // As above; on failure *error gets the backend's reason (e.g.
    // "txn-already-known", "bad-txns-inputs-missingorspent").
    bool broadcastTransaction(const std::string& signed_tx_hex, std::string* error);
    
    // Get balance of an address (0 if the lookup fails)
    uint64_t getAddressBalance(const std::string& address);
    // false if the lookup failed; true with balance (possibly 0) if
    // the backend answered.
    bool tryGetAddressBalance(const std::string& address, uint64_t& balance);

    // Where a signed transaction is. Unknown: the backend answered and
    // does not know it (never broadcast, dropped, or confirmed with every
    // output spent and no index to find it); LookupFailed: no answer.
    enum class TxState { Unknown, InMempool, Confirmed, LookupFailed };
    TxState getTxState(const std::string& signed_tx_hex, int& confirmations);
    
    // Validate Bitcoin address. Strict (checksums, version byte /
    // HRP, witness program) and for this wallet's network (default mainnet).
    bool isValidAddress(const std::string& address) const;
    // "" if valid, else why not (for error messages).
    std::string addressError(const std::string& address) const;
    void setNetwork(BitcoinNetwork network) { network_ = network; }
    BitcoinNetwork network() const { return network_; }
    
    // Set RPC credentials
    void setRPCCredentials(const std::string& url, const std::string& user, const std::string& pass);
    // Electrum backend support
    void setBitcoinBackend(const std::string& backend);
    // Stores the server list and probes it on a background thread; returns
    // immediately. The first server that answers server.version within the
    // per-call timeout becomes the active client. Until then (or if none
    // answers) the Electrum paths are skipped and the wallet degrades to the
    // RPC/mock behaviour, exactly as when no server was reachable before.
    void setElectrumServers(const std::vector<std::string>& servers);
    // Per-call Electrum deadline (connect + TLS + request + reply), in ms.
    // Applies to probes started after the call and to the active client.
    void setElectrumTimeoutMs(int timeout_ms);
    // Blocks until the background probe has finished or timeout_ms elapsed.
    // Returns true if no probe is running any more.
    bool waitForElectrumProbe(int timeout_ms);
    bool isElectrumProbeInProgress() const;
    // Aborts an in-flight probe and Electrum calls, then joins the probe thread.
    void cancelElectrumProbe();
    const std::vector<std::string>& getElectrumServers() const { return electrum_servers_; }
    const std::string& getBitcoinBackend() const { return bitcoin_backend_; }
    bool isElectrumConnected() const;
    // Wait for a transaction to reach at least min_conf confirmations (best-effort; may simulate when backends are mock)
    bool waitForConfirmations(const std::string& tx_hex_or_id, int min_conf = 2, int timeout_seconds = 120);
    // MPC / PSBT helpers (public for NetworkManager to invoke)
    std::string createPayoutPsbt(const std::string& puzzle_address, const std::vector<PayoutOutput>& outputs);
    std::string createPayoutPsbtFromUtxos(const std::string& puzzle_address, const std::vector<PayoutOutput>& outputs);
    bool verifyPartialSignature(const std::string& base_psbt_hex, const std::string& signer, const std::string& partial_psbt_hex);
    std::string combinePartialSignatures(const std::vector<std::string>& partial_psbts);
    std::string signPsbt(const std::string& psbt_hex);
    std::string signPsbtLocally(const std::string& psbt_json, const std::string& private_key_hex);
    std::string combineLocalPsbts(const std::vector<std::string>& partial_psbts_json);
    std::string finalizePsbtLocally(const std::string& psbt_json);
    std::string finalizePsbt(const std::string& psbt_hex, const std::string& combined_sig);
    // The outputs (value, scriptPubKey) of a raw transaction, legacy
    // or segwit serialization; false if it does not parse.
    struct TxOutput {
        uint64_t value_satoshis = 0;
        std::vector<unsigned char> script;
    };
    static bool decodeTxOutputs(const std::string& raw_tx_hex, std::vector<TxOutput>& out);
    // txid (display order hex) of a raw transaction, legacy or segwit
    // (the witness is not part of the txid); "" if it does not parse.
    static std::string txidOf(const std::string& raw_tx_hex);
    // id of an MPC payout proposal: sha256d (hex) of the whole PSBT
    // as proposed. It used to be the PSBT's first 16 characters, which are
    // the same for nearly every PSBT ('{"inputs":[{"...' or "cHNidP8B..."),
    // so proposals overwrote each other. "" for an empty PSBT.
    static std::string psbtId(const std::string& psbt);
    
private:
    std::string rpc_url_;
    std::string rpc_user_;
    std::string rpc_password_;
    std::string bitcoin_backend_ = "bitcoind"; // 'bitcoind' or 'electrum'
    BitcoinNetwork network_ = BitcoinNetwork::Mainnet;
    std::vector<std::string> electrum_servers_;
    // Active client, published by the probe thread; read via electrumClient().
    std::shared_ptr<ElectrumClient> electrum_client_;
    mutable std::mutex electrum_mutex_;
    std::condition_variable electrum_probe_cv_;
    bool electrum_probe_running_ = false; // guarded by electrum_mutex_
    std::thread electrum_probe_thread_;
    std::atomic<bool> electrum_abort_{false};
    std::atomic<int> electrum_timeout_ms_{3000};

    std::shared_ptr<ElectrumClient> electrumClient() const;
    void probeElectrumServers(std::vector<std::string> servers);
    
    std::string rpcCall(const std::string& method, const std::string& params);

    friend struct BitcoinWalletTestAccess;  // tests: raw RPC access
};
