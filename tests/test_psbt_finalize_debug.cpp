#include <catch2/catch_test_macros.hpp>
#include "BitcoinWallet.h"
#include "json.hpp"
#include <sstream>
#include <iomanip>
#include "EllipticCurve.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>

TEST_CASE("PSBT finalize debug basic", "[BitcoinWallet][PSBT][debug]") {
    BitcoinWallet wallet;
    EllipticCurve ec;
    std::string priv = "1e99423a4ed27608a15a2616a2b2ecb8f2f5f1fbb81450b8bf8a3db3f8b5a0a1";
    auto pubp = ec.multiplyByG(priv);
    std::string pub_hex = ec.pointToHex(pubp, true);
    // Compute hash160
    auto pubkey_bytes = std::vector<unsigned char>(); pubkey_bytes.reserve(pub_hex.size()/2);
    for (size_t i=0;i<pub_hex.size(); i+=2) pubkey_bytes.push_back(static_cast<unsigned char>(std::stoul(pub_hex.substr(i,2),nullptr,16)));
    unsigned char h1[SHA256_DIGEST_LENGTH]; unsigned char h2[RIPEMD160_DIGEST_LENGTH]; SHA256_CTX ctx; SHA256_Init(&ctx); SHA256_Update(&ctx, pubkey_bytes.data(), pubkey_bytes.size()); SHA256_Final(h1, &ctx); RIPEMD160_CTX rctx; RIPEMD160_Init(&rctx); RIPEMD160_Update(&rctx, h1, SHA256_DIGEST_LENGTH); RIPEMD160_Final(h2, &rctx);
    std::vector<unsigned char> h160(h2, h2+RIPEMD160_DIGEST_LENGTH);
    std::vector<unsigned char> spk; spk.push_back(0x00); spk.push_back(0x14); spk.insert(spk.end(), h160.begin(), h160.end());
    BitcoinWallet::Utxo u; u.txid = std::string(64,'0'); u.txid[0] = '1'; u.vout = 0; u.value_satoshis = 100000; std::vector<BitcoinWallet::Utxo> utxos; utxos.push_back(u);
    PayoutOutput pout; pout.address = std::string("1BitcoinEaterAddressDontSendf59kuE"); pout.amount_satoshis = 90000; std::vector<PayoutOutput> outputs; outputs.push_back(pout);
    std::string utx = wallet.buildRawTransaction(utxos, outputs, spk, 1000);
    REQUIRE(!utx.empty());
    nlohmann::json psbt; psbt["tx_hex"] = utx; psbt["inputs"] = nlohmann::json::array(); psbt["outputs"] = nlohmann::json::array();
    auto bytesToHexLocal = [&](const std::vector<unsigned char>& b){ std::ostringstream oss; oss<<std::hex<<std::setfill('0'); for (unsigned char c: b) oss<<std::setw(2)<<(int)c; return oss.str(); };
    nlohmann::json in; in["txid"] = u.txid; in["vout"] = u.vout; in["value"] = u.value_satoshis; in["scriptPubKey"] = bytesToHexLocal(spk); psbt["inputs"].push_back(in);
    std::string signed_psbt = wallet.signPsbtLocally(psbt.dump(), priv);
    REQUIRE(!signed_psbt.empty());
    nlohmann::json parsed = nlohmann::json::parse(signed_psbt);
    INFO("signed psbt: " << signed_psbt);
    REQUIRE(parsed["inputs"][0].contains("partial_sigs"));
    std::string combined = wallet.combineLocalPsbts({signed_psbt});
    INFO("combined: " << combined);
    std::string final_tx = wallet.finalizePsbtLocally(combined);
    INFO("final tx hex: " << final_tx);
    REQUIRE(!final_tx.empty());
}
