// PR 29: raw JSON-RPC access to a BitcoinWallet for tests (the regtest
// suite drives the node through the wallet's own transport).
#pragma once

#include <string>

#include "BitcoinWallet.h"

struct BitcoinWalletTestAccess {
    static std::string rpc(BitcoinWallet& w, const std::string& method, const std::string& params) {
        return w.rpcCall(method, params);
    }
};
