#include <catch2/catch_test_macros.hpp>
#include "BitcoinWallet.h"
#include "json.hpp"
#include <sstream>
#include <iomanip>
#include "EllipticCurve.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <string>

TEST_CASE("PSBT segwit sign and finalize P2WPKH", "[BitcoinWallet][PSBT]") {
    BitcoinWallet wallet; // will use default electrum rpc empty (but signPsbtLocally is local)
    EllipticCurve ec;
    std::string priv = "1e99423a4ed27608a15a2616a2b2ecb8f2f5f1fbb81450b8bf8a3db3f8b5a0a1";
    auto pubp = ec.multiplyByG(priv);
    std::string pub_hex = ec.pointToHex(pubp, true);
    // Compute hash160
    auto pubkey_bytes = std::vector<unsigned char>(); pubkey_bytes.reserve(pub_hex.size()/2);
    for (size_t i=0;i<pub_hex.size(); i+=2) pubkey_bytes.push_back(static_cast<unsigned char>(std::stoul(pub_hex.substr(i,2),nullptr,16)));
    unsigned char h1[SHA256_DIGEST_LENGTH]; unsigned char h2[RIPEMD160_DIGEST_LENGTH]; SHA256_CTX ctx; SHA256_Init(&ctx); SHA256_Update(&ctx, pubkey_bytes.data(), pubkey_bytes.size()); SHA256_Final(h1, &ctx); RIPEMD160_CTX rctx; RIPEMD160_Init(&rctx); RIPEMD160_Update(&rctx, h1, SHA256_DIGEST_LENGTH); RIPEMD160_Final(h2, &rctx);
    std::vector<unsigned char> h160(h2, h2+RIPEMD160_DIGEST_LENGTH);
    // scriptPubKey native p2wpkh 0x0014{20}
    std::vector<unsigned char> spk; spk.push_back(0x00); spk.push_back(0x14); spk.insert(spk.end(), h160.begin(), h160.end());
    // UTXO
    BitcoinWallet::Utxo u; u.txid = std::string(64,'0'); // fake txid; ok for unit test
    u.txid[0] = '1'; u.vout = 0; u.value_satoshis = 100000; 
    std::vector<BitcoinWallet::Utxo> utxos; utxos.push_back(u);
    // outputs: single output to placeholder p2pkh address
    PayoutOutput pout; pout.address = std::string("1BitcoinEaterAddressDontSendf59kuE"); pout.amount_satoshis = 90000; std::vector<PayoutOutput> outputs; outputs.push_back(pout);
    // Build unsigned raw tx
    std::string utx = wallet.buildRawTransaction(utxos, outputs, spk, 1000);
    REQUIRE(!utx.empty());
    // Build psbt json
    nlohmann::json psbt; psbt["tx_hex"] = utx; psbt["inputs"] = nlohmann::json::array(); psbt["outputs"] = nlohmann::json::array();
    auto bytesToHexLocal = [&](const std::vector<unsigned char>& b){ std::ostringstream oss; oss<<std::hex<<std::setfill('0'); for (unsigned char c: b) oss<<std::setw(2)<<(int)c; return oss.str(); };
    nlohmann::json in; in["txid"] = u.txid; in["vout"] = u.vout; in["value"] = u.value_satoshis; in["scriptPubKey"] = bytesToHexLocal(spk);
    psbt["inputs"].push_back(in);
    // Sign locally
    std::string signed_psbt = wallet.signPsbtLocally(psbt.dump(), priv);
    INFO("Signed PSBT.json: " << signed_psbt);
    REQUIRE(!signed_psbt.empty());
    // Combine and finalize
    std::vector<std::string> parts; parts.push_back(signed_psbt);
    std::string combined = wallet.combineLocalPsbts(parts);
    INFO("Combined PSBT: " << combined);
    auto parsed_combined = nlohmann::json::parse(combined);
    REQUIRE(parsed_combined["inputs"].size() > 0);
    REQUIRE(parsed_combined["inputs"][0].value("partial_sigs", nlohmann::json::array()).size() > 0);
    REQUIRE(!combined.empty());
    std::string final_tx = wallet.finalizePsbtLocally(combined);
    REQUIRE(!final_tx.empty());
    // Check tx contains segwit marker '0001' after version (8 hex chars then 0001)
    REQUIRE(final_tx.size() > 8+4);
    std::string marker = final_tx.substr(8,4);
    REQUIRE(marker == "0001");
}
