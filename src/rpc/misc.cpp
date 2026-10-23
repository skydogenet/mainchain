// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chain.h>
#include <clientversion.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <httpserver.h>
#include <init.h>
#include <merkleblock.h>
#include <net.h>
#include <netbase.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <timedata.h>
#include <txdb.h>
#include <util.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <miner.h>
#include <validation.h>
#ifdef ENABLE_WALLET
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#endif
#include <warnings.h>

#include <boost/thread/thread.hpp> // boost::this_thread::interruption_point

#include <stdint.h>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <univalue.h>

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    CWallet * const pwallet;

    explicit DescribeAddressVisitor(CWallet *_pwallet) : pwallet(_pwallet) {}

    void ProcessSubScript(const CScript& subscript, UniValue& obj, bool include_addresses = false) const
    {
        // Always present: script type and redeemscript
        txnouttype which_type;
        std::vector<std::vector<unsigned char>> solutions_data;
        Solver(subscript, which_type, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript.begin(), subscript.end()));

        CTxDestination embedded;
        UniValue a(UniValue::VARR);
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj = boost::apply_visitor(*this, embedded);
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript.begin(), subscript.end()));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
            if (include_addresses) a.push_back(EncodeDestination(embedded));
        } else if (which_type == TX_MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            // TODO: abstract out the common functionality between this logic and ExtractDestinations.
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                if (include_addresses) a.push_back(EncodeDestination(key.GetID()));
                pubkeys.push_back(HexStr(key.begin(), key.end()));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }

        // The "addresses" field is confusing because it refers to public keys using their P2PKH address.
        // For that reason, only add the 'addresses' field when needed for backward compatibility. New applications
        // can use the 'embedded'->'address' field for P2SH or P2WSH wrapped addresses, and 'pubkeys' for
        // inspecting multisig participants.
        if (include_addresses) obj.pushKV("addresses", std::move(a));
    }

    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("iswitness", false));
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        obj.push_back(Pair("iswitness", false));
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            ProcessSubScript(subscript, obj, true);
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("iswitness", true));
        obj.push_back(Pair("witness_version", 0));
        obj.push_back(Pair("witness_program", HexStr(id.begin(), id.end())));
        if (pwallet && pwallet->GetPubKey(CKeyID(id), pubkey)) {
            obj.push_back(Pair("pubkey", HexStr(pubkey)));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        obj.push_back(Pair("iswitness", true));
        obj.push_back(Pair("witness_version", 0));
        obj.push_back(Pair("witness_program", HexStr(id.begin(), id.end())));
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (pwallet && pwallet->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("iswitness", true));
        obj.push_back(Pair("witness_version", (int)id.version));
        obj.push_back(Pair("witness_program", HexStr(id.program, id.program + id.length)));
        return obj;
    }
};
#endif

UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given bitcoin address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The bitcoin address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\",        (string) The bitcoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean, optional) If the address is P2SH or P2WSH. Not included for unknown witness types.\n"
            "  \"iswitness\" : true|false,     (boolean) If the address is P2WPKH, P2WSH, or an unknown witness version\n"
            "  \"witness_version\" : version   (number, optional) For all witness output types, gives the version number.\n"
            "  \"witness_program\" : \"hex\"     (string, optional) For all witness output types, gives the script or key hash present in the address.\n"
            "  \"script\" : \"type\"             (string, optional) The output script type. Only if \"isscript\" is true and the redeemscript is known. Possible types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash, witness_v0_scripthash, witness_unknown\n"
            "  \"hex\" : \"hex\",                (string, optional) The redeemscript for the P2SH or P2WSH address\n"
            "  \"addresses\"                   (string, optional) Array of addresses associated with the known redeemscript (only if \"iswitness\" is false). This field is superseded by the \"pubkeys\" field and the address inside \"embedded\".\n"
            "    [\n"
            "      \"address\"\n"
            "      ,...\n"
            "    ]\n"
            "  \"pubkeys\"                     (string, optional) Array of pubkeys associated with the known redeemscript (only if \"script\" is \"multisig\")\n"
            "    [\n"
            "      \"pubkey\"\n"
            "      ,...\n"
            "    ]\n"
            "  \"sigsrequired\" : xxxxx        (numeric, optional) Number of signatures required to spend multisig output (only if \"script\" is \"multisig\")\n"
            "  \"pubkey\" : \"publickeyhex\",    (string, optional) The hex value of the raw public key, for single-key addresses (possibly embedded in P2SH or P2WSH)\n"
            "  \"embedded\" : {...},           (object, optional) information about the address embedded in P2SH or P2WSH, if relevant and known. It includes all validateaddress output fields for the embedded address, excluding \"isvalid\", metadata (\"timestamp\", \"hdkeypath\", \"hdmasterkeyid\") and relation to the wallet (\"ismine\", \"iswatchonly\", \"account\").\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "  \"timestamp\" : timestamp,      (number, optional) The creation time of the key if available in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );

#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

#ifdef ENABLE_WALLET
        isminetype mine = pwallet ? IsMine(*pwallet, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", bool(mine & ISMINE_SPENDABLE)));
        ret.push_back(Pair("iswatchonly", bool(mine & ISMINE_WATCH_ONLY)));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(pwallet), dest);
        ret.pushKVs(detail);
        if (pwallet && pwallet->mapAddressBook.count(dest)) {
            ret.push_back(Pair("account", pwallet->mapAddressBook[dest].name));
        }
        if (pwallet) {
            const CKeyMetadata* meta = nullptr;
            CKeyID key_id = GetKeyForDestination(*pwallet, dest);
            if (!key_id.IsNull()) {
                auto it = pwallet->mapKeyMetadata.find(key_id);
                if (it != pwallet->mapKeyMetadata.end()) {
                    meta = &it->second;
                }
            }
            if (!meta) {
                auto it = pwallet->m_script_metadata.find(CScriptID(scriptPubKey));
                if (it != pwallet->m_script_metadata.end()) {
                    meta = &it->second;
                }
            }
            if (meta) {
                ret.push_back(Pair("timestamp", meta->nCreateTime));
                if (!meta->hdKeypath.empty()) {
                    ret.push_back(Pair("hdkeypath", meta->hdKeypath));
                    ret.push_back(Pair("hdmasterkeyid", meta->hdMasterKeyID.GetHex()));
                }
            }
        }
#endif
    }
    return ret;
}

// Needed even with !ENABLE_WALLET, to pass (ignored) pointers around
class CWallet;

UniValue createmultisig(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 2)
    {
        std::string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"
            "\nArguments:\n"
            "1. nrequired                    (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"                       (string, required) A json array of hex-encoded public keys\n"
            "     [\n"
            "       \"key\"                    (string) The hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 public keys\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); ++i) {
        if (IsHex(keys[i].get_str()) && (keys[i].get_str().length() == 66 || keys[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys[i].get_str()));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid public key: %s\nNote that from v0.16, createmultisig no longer accepts addresses."
            " Users must use addmultisigaddress to create multisig addresses with addresses known to the wallet.", keys[i].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    CScriptID innerID(inner);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", EncodeDestination(innerID)));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifymessage \"address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The bitcoin address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&destination);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == *keyID);
}

UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessagewithprivkey \"privkey\" \"message\"\n"
            "\nSign a message with the private key of an address\n"
            "\nArguments:\n"
            "1. \"privkey\"         (string, required) The private key to sign the message with.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        );

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strPrivkey);
    if (!fGood)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    CKey key = vchSecret.GetKey();
    if (!key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("setmocktime for regression testing (-regtest mode) only");

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("used", uint64_t(stats.used)));
    obj.push_back(Pair("free", uint64_t(stats.free)));
    obj.push_back(Pair("total", uint64_t(stats.total)));
    obj.push_back(Pair("locked", uint64_t(stats.locked)));
    obj.push_back(Pair("chunks_used", uint64_t(stats.chunks_used)));
    obj.push_back(Pair("chunks_free", uint64_t(stats.chunks_free)));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getmemoryinfo (\"mode\")\n"
            "Returns an object containing information about memory usage.\n"
            "Arguments:\n"
            "1. \"mode\" determines what kind of information is returned. This argument is optional, the default mode is \"stats\".\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+).\n"
            "\nResult (mode \"stats\"):\n"
            "{\n"
            "  \"locked\": {               (json object) Information about locked memory manager\n"
            "    \"used\": xxxxx,          (numeric) Number of bytes used\n"
            "    \"free\": xxxxx,          (numeric) Number of bytes available in current arenas\n"
            "    \"total\": xxxxxxx,       (numeric) Total number of bytes managed\n"
            "    \"locked\": xxxxxx,       (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n"
            "    \"chunks_used\": xxxxx,   (numeric) Number allocated chunks\n"
            "    \"chunks_free\": xxxxx,   (numeric) Number unused chunks\n"
            "  }\n"
            "}\n"
            "\nResult (mode \"mallocinfo\"):\n"
            "\"<malloc version=\"1\">...\"\n"
            "\nExamples:\n"
            + HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
        );

    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("locked", RPCLockedMemoryInfo()));
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
}

uint32_t getCategoryMask(UniValue cats) {
    cats = cats.get_array();
    uint32_t mask = 0;
    for (unsigned int i = 0; i < cats.size(); ++i) {
        uint32_t flag = 0;
        std::string cat = cats[i].get_str();
        if (!GetLogCategory(&flag, &cat)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
        if (flag == BCLog::NONE) {
            return 0;
        }
        mask |= flag;
    }
    return mask;
}

UniValue logging(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "logging ( <include> <exclude> )\n"
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + ListLogCategories() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            "  - \"none\", \"0\" : even if other logging categories are specified, ignore all of them.\n"
            "\nArguments:\n"
            "1. \"include\"        (array of strings, optional) A json array of categories to add debug logging\n"
            "     [\n"
            "       \"category\"   (string) the valid logging category\n"
            "       ,...\n"
            "     ]\n"
            "2. \"exclude\"        (array of strings, optional) A json array of categories to remove debug logging\n"
            "     [\n"
            "       \"category\"   (string) the valid logging category\n"
            "       ,...\n"
            "     ]\n"
            "\nResult:\n"
            "{                   (json object where keys are the logging categories, and values indicates its status\n"
            "  \"category\": 0|1,  (numeric) if being debug logged or not. 0:inactive, 1:active\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], \"[libevent]\"")
        );
    }

    uint32_t originalLogCategories = logCategories;
    if (request.params[0].isArray()) {
        logCategories |= getCategoryMask(request.params[0]);
    }

    if (request.params[1].isArray()) {
        logCategories &= ~getCategoryMask(request.params[1]);
    }

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    uint32_t changedLogCategories = originalLogCategories ^ logCategories;
    if (changedLogCategories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(logCategories & BCLog::LIBEVENT)) {
            logCategories &= ~BCLog::LIBEVENT;
            if (changedLogCategories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    std::vector<CLogCategoryActive> vLogCatActive = ListActiveLogCategories();
    for (const auto& logCatActive : vLogCatActive) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
}

UniValue createcriticaldatatx(const JSONRPCRequest& request)
{
    // TODO finish
    //
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "createcriticaldatatx\n"
            "Create a critical data transaction\n"
            "\nArguments:\n"
            "1. \"amount\"         (numeric or string, required) The amount in " + CURRENCY_UNIT + " to be spent.\n"
            "2. \"height\"         (numeric, required) The block height this transaction must be included in.\n"
            "3. \"criticalhash\"   (string, required) h* you want added to a coinbase\n"
            "\nExamples:\n"
            + HelpExampleCli("createcriticaldatatx", "\"amount\", \"height\", \"criticalhash\"")
            + HelpExampleRpc("createcriticaldatatx", "\"amount\", \"height\", \"criticalhash\"")
            );

    // TODO remove after finished
    throw JSONRPCError(RPC_INTERNAL_ERROR, "Sorry, this function is not supported yet.");

    // Amount
    CAmount nAmount = AmountFromValue(request.params[0]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    int nHeight = request.params[1].get_int();

    // Critical hash
    uint256 hashCritical = uint256S(request.params[2].get_str());
    if (hashCritical.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid h*");

#ifdef ENABLE_WALLET
    // Create and send the transaction
    std::string strError;
    if (vpwallets.empty()){
        strError = "Error: no wallets are available";
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    std::vector<CRecipient> vecSend;
    CRecipient recipient = {CScript() << OP_0, nAmount, false};
    vecSend.push_back(recipient);

    LOCK2(cs_main, vpwallets[0]->cs_wallet);

    CWalletTx wtx;
    CReserveKey reservekey(vpwallets[0]);
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    //TODO: set this as a real thing
    CCoinControl cc;
    if (!vpwallets[0]->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, cc)) {
        if (nAmount + nFeeRequired > vpwallets[0]->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!vpwallets[0]->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    UniValue ret(UniValue::VOBJ);
#ifdef ENABLE_WALLET
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));
    ret.push_back(Pair("nChangePos", nChangePosRet));
#endif

    return ret;
}

UniValue listsidechainctip(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "listsidechainctip\n"
            "Returns the crtitical transaction index pair for nSidechain\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (numeric, required) The sidechain number\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechainctip", "\"nsidechain\"")
            + HelpExampleRpc("listsidechainctip", "\"nsidechain\"")
            );

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // Security fix (SCDB read race): the global scdb is move-assigned wholesale
    // by ConnectBlock under cs_main, so every read of it must hold cs_main too.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    SidechainCTIP ctip;
    if (!scdb.GetCTIP(nSidechain, ctip))
        throw JSONRPCError(RPC_MISC_ERROR, "No CTIP found for sidechain!");

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", ctip.out.hash.ToString()));
    obj.push_back(Pair("n", (int64_t)ctip.out.n));
    obj.push_back(Pair("amount", ctip.amount));
    obj.push_back(Pair("amountformatted", FormatMoney(ctip.amount)));

    return obj;
}

UniValue listsidechaindeposits(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "listsidechaindeposits\n"
            "List the most recent cached deposits for sidechain.\n"
            "Optionally limited to count. Note that this only has access to "
            "deposits which are currently cached.\n"
            "\nArguments:\n"
            "1. \"nsidechain\"  (numeric, required) The sidechain number\n"
            "2. \"txid\"        (string, optional) Only return deposits after this deposit TXID\n"
            "3. \"n\"           (numeric, optional, required if txid is set) The output index of the previous argument txn\n"
            "4. \"count\"       (numeric, optional) The number of most recent deposits to list\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechaindeposits", "\"sidechainkey\", \"count\"")
            + HelpExampleRpc("listsidechaindeposits", "\"sidechainkey\", \"count\"")
            );

#ifdef ENABLE_WALLET
    // Check for active wallet
    std::string strError;
    if (vpwallets.empty()) {
        strError = "Error: no wallets are available";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    // Check sidechain number
    int nSidechain = request.params[0].get_int();
    if (nSidechain < 0 || nSidechain > 255)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // If TXID was passed in, make sure we also received N
    if (request.params.size() > 1 && request.params.size() < 3) {
        std::string strError = "Output index 'n' is required if TXID is provided!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Was a TXID passed in?
    uint256 txidKnown;
    if (request.params.size() > 1) {
        std::string strTXID = request.params[1].get_str();
        txidKnown = uint256S(strTXID);
        if (txidKnown.IsNull()) {
            std::string strError = "Invalid TXID!";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
    }

    // Was N passed in?
    uint32_t nKnown = 0;
    if (request.params.size() > 2) {
        nKnown = request.params[2].get_int();
    }

    // Get number of recent deposits to return (default is all cached deposits)
    bool fLimit = false;
    int count = 0;
    if (request.params.size() == 4) {
        fLimit = true;
        count = request.params[3].get_int();
    }

    UniValue arr(UniValue::VARR);

#ifdef ENABLE_WALLET
    // Security fix (SCDB read race): the global scdb is move-assigned wholesale
    // by ConnectBlock under cs_main, so hold cs_main across the deposit read and
    // the mapBlockIndex lookups in the loop below (which also require it).
    LOCK(cs_main);

    std::vector<SidechainDeposit> vDeposit = scdb.GetDeposits(nSidechain);

    for (auto rit = vDeposit.crbegin(); rit != vDeposit.crend(); rit++) {
        const SidechainDeposit d = *rit;

        // Check if we have reached a deposit the sidechain already has. The
        // sidechain can pass in a TXID & output index 'n' to let us know what
        // the latest deposit they've already received is.
        if (!txidKnown.IsNull() && d.tx.GetHash() == txidKnown && d.nBurnIndex == nKnown)
        {
            LogPrintf("%s: Reached known deposit. TXID: %s n: %u\n",
                    __func__, txidKnown.ToString(), nKnown);
            break;
        }

        // Add deposit txid to set
        uint256 txid = d.tx.GetHash();
        std::set<uint256> setTxids;
        setTxids.insert(txid);

        BlockMap::iterator it = mapBlockIndex.find(d.hashBlock);
        if (it == mapBlockIndex.end()) {
            std::string strError = "Block hash not found";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
        }

        CBlockIndex* pblockindex = it->second;
        if (pblockindex == NULL) {
            std::string strError = "Block index null";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
        }

        if (!chainActive.Contains(pblockindex)) {
            std::string strError = "Block not in active chain";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
        }
#endif

#ifdef ENABLE_WALLET
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("nsidechain", d.nSidechain));
        obj.push_back(Pair("strdest", d.strDest));
        obj.push_back(Pair("txhex", EncodeHexTx(d.tx)));
        obj.push_back(Pair("nburnindex", (int)d.nBurnIndex));
        obj.push_back(Pair("ntx", (int)d.nTx));
        obj.push_back(Pair("hashblock", d.hashBlock.ToString()));

        arr.push_back(obj);
#endif
        if (fLimit) {
            count--;
            if (count <= 0)
                break;
        }
    }

    return arr;
}

UniValue countsidechaindeposits(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "countsidechaindeposits\n"
            "Returns the number of deposits (for nSidechain) currently cached. "
            "Note that this doesn't count all sidechain deposits, just the "
            "number currently cached by the node.\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (numeric, required) The sidechain number\n"
            "\nExamples:\n"
            + HelpExampleCli("countsidechaindeposits", "\"nsidechain\"")
            + HelpExampleRpc("countsidechaindeposits", "\"nsidechain\"")
            );

#ifdef ENABLE_WALLET
    // Check for active wallet
    std::string strError;
    if (vpwallets.empty()) {
        strError = "Error: no wallets are available";
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // Security fix (SCDB read race): the global scdb is move-assigned wholesale
    // by ConnectBlock under cs_main, so every read of it must hold cs_main too.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number");

    int count = 0;

    // Get latest deposit from sidechain DB deposit cache
    std::vector<SidechainDeposit> vDeposit = scdb.GetDeposits(nSidechain);
    count = vDeposit.size();

    return count;
}

UniValue addwithdrawal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "addwithdrawal\n"
            "For testing purposes only! Add withdrawal to SCDB\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (int, required) Sidechain number\n"
            "2. \"hash\"            (string, required) Bundle hash\n"
            "\nExamples:\n"
            + HelpExampleCli("addwithdrawal", "")
            + HelpExampleRpc("addwithdrawal", "")
    );

    // Testing only, and enforced rather than advisory: this writes straight
    // into the global sidechain database with no block behind it, so on a real
    // network it would leave this node's consensus state disagreeing with every
    // peer's. Same gate as setmocktime.
    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("addwithdrawal is for regression testing (-regtest mode) only");

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // Block connection copies the SCDB, mutates the copy, and publishes it back
    // wholesale, so an SCDB write made from this thread while that is in flight
    // would be discarded without any error being reported. Hold cs_main across
    // the read-modify-write (chainActive is read below and needs it regardless).
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain)) {
        std::string strError = "Invalid sidechain number!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    uint256 hash = uint256S(request.params[1].get_str());
    if (hash.IsNull()) {
        std::string strError = "Invalid bundle hash!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Pass an explicit height so the new nHeight parameter is not silently
    // bound from the bool literal (which would seed legacy params and drop
    // fDebug). This RPC seeds SCDB state, so it must use the height whose
    // rules apply to the next block.
    if (!scdb.AddWithdrawal(nSidechain, hash, chainActive.Height() + 1, true /* fDebug */)) {
        std::string strError = "Failed to add withdrawal!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    return NullUniValue;
}

UniValue receivewithdrawalbundle(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "receivewithdrawalbundle\n"
            "Called by sidechain to announce new withdrawal for verification\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (int, required) The sidechain number\n"
            "2. \"rawtx\"           (string, required) The raw transaction hex\n"
            "\nExamples:\n"
            + HelpExampleCli("receivewithdrawalbundle", "")
            + HelpExampleRpc("receivewithdrawalbundle", "")
     );

#ifndef ENABLE_WALLET
    strError = "Error: Wallet disabled";
    LogPrintf("%s: %s\n", __func__, strError);
    throw JSONRPCError(RPC_WALLET_ERROR, strError);
#endif

#ifdef ENABLE_WALLET
    // Check for active wallet
    std::string strError;
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        strError = "Error: no wallets are available";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // Block connection copies the SCDB, mutates the copy, and publishes it back
    // wholesale, so a bundle cached from this thread while that is in flight
    // would be dropped even though this call reported success. Hold cs_main
    // across the whole read-modify-write.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain)) {
        strError = "Invalid sidechain number!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Create CTransaction from hex
    CMutableTransaction mtx;
    std::string hex = request.params[1].get_str();
    if (!DecodeHexTx(mtx, hex)) {
        strError = "Invalid transaction hex!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    CTransaction withdrawal(mtx);

    if (withdrawal.IsNull()) {
        strError = "Invalid withdrawal hex";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // The bundle is
    // cached, committed and voted on by its own hash, but a payout is approved
    // by CTransaction::GetBlindHash(payout). CreateWithdrawalPayout builds the
    // payout as version 2, lock time 0, the treasury input (final sequence),
    // the bundle's outputs and then the change return; GetBlindHash replaces
    // the inputs with one default input (null outpoint, final sequence) whose
    // scriptSig is OP_0 and pops the change return. So the only bundle that
    // can ever be paid is exactly that form. A bundle in any other form would
    // gather votes for the whole period and then be skipped by every miner
    // until it failed - refused here instead. RPC policy only, no consensus
    // change; not suspended by -drivechainpolicybypass, because such a bundle
    // is unpayable under every rule set.
    {
        CMutableTransaction canon;
        canon.nVersion = 2;
        canon.nLockTime = 0;
        canon.vin.resize(1);
        canon.vin[0].scriptSig = CScript() << OP_0;
        canon.vout = mtx.vout;
        if (CTransaction(canon).GetHash() != withdrawal.GetHash()) {
            strError = "Rejecting withdrawal: not in the canonical bundle form (version 2, lock time 0, "
                       "one input with a null outpoint, scriptSig OP_0 and the final sequence, then the "
                       "bundle outputs) - it could be voted on but never paid out";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
        }
    }

    // Reject the withdrawal if it spends more than the sidechain's CTIP as it won't
    // be accepted anyway
    CAmount amount = withdrawal.GetValueOut();
    std::vector<COutput> vSidechainCoin;
    CScript scriptPubKey;
    if (!scdb.GetSidechainScript(nSidechain, scriptPubKey)) {
        strError = "Cannot get script for sidechain!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    SidechainCTIP ctip;
    if (!scdb.GetCTIP(nSidechain, ctip)) {
        strError = "Rejecting withdrawal: No CTIP found!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    if (amount > ctip.amount) {
        strError = "Rejecting withdrawal: Withdrawn amount greater than CTIP amount!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Check for the required withdrawal change return destination OP_RETURN output
    for (size_t i = 0; i < mtx.vout.size(); i++) {
        const CScript& scriptPubKey = mtx.vout[i].scriptPubKey;
        if (!scriptPubKey.size())
            continue;
        if (scriptPubKey.front() != OP_RETURN)
            continue;

        if (scriptPubKey.size() < 3) {
            strError = "Rejecting Withdrawal: First OP_RETURN output invalid size (too small)!\n";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }

        CScript::const_iterator pDest = scriptPubKey.begin() + 1;
        opcodetype opcode;
        std::vector<unsigned char> vch;
        if (!scriptPubKey.GetOp(pDest, opcode, vch) || vch.empty()) {
            strError = "Rejecting Withdrawal: First OP_RETURN output invalid. (Failed GetOp)!\n";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
        std::string strDest((const char*)vch.data(), vch.size());
        if (strDest != SIDECHAIN_WITHDRAWAL_RETURN_DEST) {
            strError = "Rejecting Withdrawal: First OP_RETURN output invalid. (incorrect dest)!\n";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
        break;
    }

    // The payout is assembled by the miner, which appends the sidechain change
    // return output and the CTIP input itself. So a bundle must arrive with
    // neither: the destinations, the encoded fee and the "D" output only.
    //
    // A bundle that already carries a sidechain output produces a payout with two
    // of them, whose value exceeds the CTIP. Nothing rejects that until a block
    // template is assembled, and there it surfaces as a TestBlockValidity failure
    // that aborts CreateNewBlock - which stops the node producing blocks at all,
    // for any purpose, and survives restart because the bundle is written to
    // withdrawal.dat. Catch it here instead, where the error can be reported to
    // whoever submitted it.
    for (const CTxOut& out : withdrawal.vout) {
        uint8_t nSidechainOut;
        if (out.scriptPubKey.IsDrivechain(nSidechainOut)) {
            strError = "Rejecting Withdrawal: bundle must not contain a sidechain change output - the payout adds it!";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
    }

    // The amount check above compares only the outputs against the CTIP. The
    // payout also has to cover the mainchain fees encoded in the second output,
    // so verify the whole sum closes before the bundle is cached. Both figures
    // are already known here.
    if (withdrawal.vout.size() < 3) {
        strError = "Rejecting Withdrawal: too few outputs - expected the return destination, the encoded fee, and at least one payout!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }
    CAmount amountBundleFees = 0;
    if (!DecodeWithdrawalFees(withdrawal.vout[1].scriptPubKey, amountBundleFees)) {
        strError = "Rejecting Withdrawal: could not decode the mainchain fee output!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }
    // Escrow rules (BIP300 796c80eb): the fee output must be zero-value. From
    // EscrowRulesHeight a payout of such a bundle is invalid, so caching it
    // would only collect votes for a bundle that can never be paid. Refused
    // regardless of height - every honest bundle builder writes 0 here.
    // Node-local policy, suspended by -drivechainpolicybypass (regtest only).
    if (withdrawal.vout[1].nValue != 0 && !fDrivechainPolicyBypass) {
        strError = "Rejecting Withdrawal: the mainchain fee output must carry no value!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }
    // The change requirement - and only that requirement, the range checks
    // beside it stand either way - is suspended by -drivechainpolicybypass.
    // This guard is node-local RPC policy, and the bundle it refuses reaches a
    // cooperating miner as raw bytes without passing through here at all, so a
    // test that has to ask what the layers behind it do needs the bundle
    // cached exactly as LoadWithdrawalCache would cache one. Regtest only.
    if (!MoneyRange(amountBundleFees) || !MoneyRange(amount) ||
            amount > MAX_MONEY - amountBundleFees ||
            (amount + amountBundleFees >= ctip.amount && !fDrivechainPolicyBypass)) {
        // Equality is refused as well as excess: a bundle that takes the whole
        // treasury would leave a zero-value change output, which would close
        // the sidechain's peg. Leave a remainder instead.
        strError = "Rejecting Withdrawal: withdrawn amount plus mainchain fees "
                   "must leave a non-zero change output - a bundle that empties "
                   "the treasury would close the sidechain's peg permanently.";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Small-block soft fork: bundles that cannot fit in a 50 KB block will
    // never be paid out - reject them at ingestion so the sidechain can split
    // the withdrawal into smaller bundles instead of stalling. (This check is
    // deliberately not in CacheWithdrawalTx itself: LoadWithdrawalCache must
    // still be able to reload legacy oversized bundles from disk.)
    //
    // Gated on the same activation height as every other small-block rule. The
    // rule is deferred, so until the flag day the block size limit is unchanged
    // and a larger bundle is still perfectly payable; rejecting it early would
    // stall withdrawals that the rest of the network happily pays out.
    const int nNextHeight = chainActive.Height() + 1;
    if (nNextHeight >= Params().GetConsensus().SmallBlockHeight &&
            ::GetSerializeSize(withdrawal, SER_NETWORK, PROTOCOL_VERSION) > SIDECHAIN_MAX_WITHDRAWAL_BUNDLE_BYTES) {
        strError = strprintf("Rejecting Withdrawal: bundle is larger than %u bytes and could never be paid out in a small block!", SIDECHAIN_MAX_WITHDRAWAL_BUNDLE_BYTES);
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }
    // The fixed cap above is the most a bundle may ever be; the room actually
    // left for a payout is smaller, and shrinks with every active sidechain
    // and pending proposal the coinbase must carry commitments for. A bundle
    // that passes the fixed cap but not the live room would be cached, voted
    // to the threshold, and then deferred by the assembler on every block
    // ("no room in small block") - and because each block's vote for a slot
    // downvotes every other withdrawal of that slot, nothing smaller could
    // overtake it until it expired. Refuse it at the door instead, with the
    // number the sidechain has to fit under. Measured in the enforced
    // (charged) measure, as the assembler budgets.
    if (nNextHeight >= Params().GetConsensus().SmallBlockHeight) {
        const uint64_t nRoom = SmallBlockPayoutRoomBytes(nNextHeight);
        const uint64_t nBundle = GetChargedSerializedSize(withdrawal);
        if (nBundle > nRoom) {
            strError = strprintf("Rejecting Withdrawal: bundle is %u bytes but at most %u bytes can be paid out beside the coinbase commitments of the %u active sidechains - split it",
                                 nBundle, nRoom, scdb.GetActiveSidechainCount());
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
    }

    // Add Withdrawal to our local cache so that we can create a Withdrawal hash commitment
    // in the next block we mine to begin the verification process
    if (!scdb.CacheWithdrawalTx(withdrawal, nSidechain)) {
        strError = "Withdrawal rejected from cache (duplicate?)";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Return Withdrawal hash to verify it has been received
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("wtxid", withdrawal.GetHash().GetHex()));
    return ret;
}

UniValue verifybmm(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifybmm\n"
            "Check if a mainchain block includes BMM for a sidechain h*\n"
            "\nArguments:\n"
            "1. \"blockhash\"      (string, required) mainchain blockhash with h*\n"
            "2. \"bmmhash\"        (string, required) h* to locate\n"
            "3. \"nsidechain\"     (number, required) sidechain number\n"
            "\nExamples:\n"
            + HelpExampleCli("verifybmm", "\"blockhash\", \"bmmhash\", \"nsidechain\"")
            + HelpExampleRpc("verifybmm", "\"blockhash\", \"bmmhash\", \"nsidechain\"")
            );

    uint256 hashBlock = uint256S(request.params[0].get_str());
    uint256 hashBMM = uint256S(request.params[1].get_str());
    int nSidechain = request.params[2].get_int();

    // Is nSidechain valid?
    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // Security fix (reorg-race crash + SCDB read race): hold cs_main across the
    // scdb read below and the mapBlockIndex reads and ReadBlockFromDisk further
    // down. The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, and a concurrent block connect/reorg can rehash mapBlockIndex or
    // prune the CBlockIndex out from under this read (undefined behaviour /
    // segfault) otherwise.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain)) {
        std::string strError = "Invalid sidechain number!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    if (!mapBlockIndex.count(hashBlock)) {
        std::string strError = "Block not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];
    if (pblockindex == NULL)
    {
        std::string strError = "pblockindex null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // A commitment only counts if the block
    // carrying it is in the ACTIVE chain. mapBlockIndex also holds stale and
    // invalid blocks (and ReadBlockFromDisk reads them), so a sidechain asking
    // about a block that a reorg orphaned was told its h* was there - and a
    // sidechain block whose commitment the mainchain no longer has stayed
    // acceptable. RPC answer only, not consensus, no flag day.
    if (!chainActive.Contains(pblockindex)) {
        std::string strError = "Block not in active chain";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
    {
        std::string strError = "Failed to read block from disk";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    if (!block.vtx.size()) {
        std::string strError = "No txns in block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    bool fBMMFound = false;
    const CTransaction &txCoinbase = *(block.vtx[0]);
    for (const CTxOut& out : txCoinbase.vout) {
        const CScript& scriptPubKey = out.scriptPubKey;

        uint256 hashCritical = uint256();
        std::vector<unsigned char> vBytes;
        if (!scriptPubKey.IsCriticalHashCommit(hashCritical, vBytes))
            continue;

        // Create critical data object and validate BMM
        CCriticalData data;
        data.hashCritical = hashCritical;
        data.vBytes = vBytes;

        uint8_t nSidechainBMM;
        std::string strPrevBlock = "";
        if (!data.IsBMMRequest(nSidechainBMM, strPrevBlock))
            continue;

        // Check sidechain number
        if (nSidechain != nSidechainBMM)
            continue;

        // Check prev block bytes
        if (strPrevBlock != block.hashPrevBlock.ToString().substr(56, 63))
            continue;

        // Check h*
        if (hashBMM == data.hashCritical)
            fBMMFound = true;
    }

    if (!fBMMFound) {
        std::string strError = "h* not found in block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    UniValue ret(UniValue::VOBJ);
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", txCoinbase.GetHash().ToString()));
    obj.push_back(Pair("time", itostr(block.nTime)));
    ret.push_back(Pair("bmm", obj));

    return ret;
}

UniValue verifydeposit(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifydeposit\n"
            "Check if a mainchain block includes valid deposit with txid.\n"
            "\nArguments:\n"
            "1. \"blockhash\"      (string, required) mainchain blockhash with deposit\n"
            "2. \"txid\"           (string, required) deposit txid to locate\n"
            "3. \"nTx\"            (int, required) deposit tx number in block\n"
            "\nExamples:\n"
            + HelpExampleCli("verifybmm", "\"blockhash\", \"txid\"")
            + HelpExampleRpc("verifybmm", "\"blockhash\", \"txid\"")
            );

    uint256 hashBlock = uint256S(request.params[0].get_str());
    uint256 txid = uint256S(request.params[1].get_str());
    int nTx = request.params[2].get_int();

    // Security fix (reorg-race crash): hold cs_main across the mapBlockIndex
    // reads and ReadBlockFromDisk below (see verifybmm).
    LOCK(cs_main);

    if (!mapBlockIndex.count(hashBlock)) {
        std::string strError = "Block not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];
    if (pblockindex == NULL)
    {
        std::string strError = "pblockindex null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    // A deposit is only real if the block carrying it is in the ACTIVE chain.
    // mapBlockIndex also holds stale and invalid blocks, so without this a
    // sidechain asking about a deposit in an orphaned block was answered with
    // its txid, i.e. "valid". This is the one bind the sidechain's
    // VerifyDeposit(hashMainBlock, txid, nTx) cannot make for itself, and the
    // same check verifybmm-style callers already make for BMM commitments.
    if (!chainActive.Contains(pblockindex)) {
        std::string strError = "Block not in active chain";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    if (!scdb.HaveDepositCached(txid)) {
        std::string strError = "SCDB does not know deposit";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
    {
        std::string strError = "Failed to read block from disk";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    if (!block.vtx.size()) {
        std::string strError = "No txns in block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    // Security fix: also reject a negative nTx, otherwise block.vtx[nTx] below
    // is an out-of-bounds vector read (the upper-bound check alone let a
    // negative index through).
    if (nTx < 0 || (int)block.vtx.size() <= nTx) {
        std::string strError = "nTx out of range for block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    const CTransaction &tx = *(block.vtx[nTx]);
    if (tx.GetHash() != txid) {
        std::string strError = "Transaction at block index specified does not match txid";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    SidechainDeposit deposit;
    if (!scdb.TxnToDeposit(tx, nTx, hashBlock, deposit)) {
        std::string strError = "Invalid deposit transaction format";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    return tx.GetHash().ToString();
}

UniValue listpreviousblockhashes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listpreviousblockhashes\n"
            "List the 5 most recent mainchain block hashes. Used by sidechains " \
            "to help search for BMM commitments.\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listpreviousblockhashes", "")
            + HelpExampleRpc("listpreviousblockhashes", "")
            );

    // Security fix (reorg-race crash): hold cs_main across the chainActive
    // reads so a concurrent reorg cannot shrink the chain between the height
    // read and chainActive[i], which would return null and crash the node.
    LOCK(cs_main);

    int nHeight = chainActive.Height();
    int nStart = nHeight - 4;
    if (!(nHeight > 0) || !(nStart > 0))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Insufficient blocks connected to complete request!");

    std::vector<uint256> vHash;
    for (int i = nStart; i <= nHeight; i++) {
        uint256 hashBlock = chainActive[i]->GetBlockHash();
        vHash.push_back(hashBlock);
    }

    UniValue ret(UniValue::VARR);
    for (const uint256& hash : vHash) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("hash", hash.ToString()));
        ret.push_back(obj);
    }

    return ret;
}

UniValue listactivesidechains(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listactivesidechains\n"
            "List active sidechains.\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listactivesidechains", "")
            + HelpExampleRpc("listactivesidechains", "")
            );

    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    std::vector<Sidechain> vActive = scdb.GetActiveSidechains();
    UniValue ret(UniValue::VARR);
    for (const Sidechain& s : vActive) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.title));
        obj.push_back(Pair("description", s.description));
        obj.push_back(Pair("nversion", s.nVersion));
        obj.push_back(Pair("hashid1", s.hashID1.ToString()));
        obj.push_back(Pair("hashid2", s.hashID2.ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listsidechainactivationstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listsidechainactivationstatus\n"
            "List activation status of all pending sidechains.\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechainactivationstatus", "")
            + HelpExampleRpc("listsidechainactivationstatus", "")
            );

    std::vector<SidechainActivationStatus> vStatus;
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    vStatus = scdb.GetSidechainActivationStatus();

    UniValue ret(UniValue::VARR);
    for (const SidechainActivationStatus& s : vStatus) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.proposal.title));
        obj.push_back(Pair("description", s.proposal.description));
        obj.push_back(Pair("nage", s.nAge));
        obj.push_back(Pair("nfail", s.nFail));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listsidechainproposals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listsidechainproposals\n"
            "List your own cached sidechain proposals\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechainproposals", "")
            + HelpExampleRpc("listsidechainproposals", "")
            );

    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    std::vector<Sidechain> vProposal = scdb.GetSidechainProposals();
    UniValue ret(UniValue::VARR);
    for (const Sidechain& s : vProposal) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.title));
        obj.push_back(Pair("description", s.description));
        obj.push_back(Pair("nversion", s.nVersion));
        obj.push_back(Pair("hashid1", s.hashID1.ToString()));
        obj.push_back(Pair("hashid2", s.hashID2.ToString()));

        ret.push_back(obj);
    }

    return ret;
}


UniValue acksidechain(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
            "acksidechain\n"
            "acksidechain sidechain proposals\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("acksidechain", "")
            + HelpExampleRpc("acksidechain", "")
            );
    uint256 strSChash = uint256S(request.params[0].get_str());

    // The SCDB is republished wholesale on block connection; without cs_main
    // this ACK can be discarded without the caller being told.
    LOCK(cs_main);

    scdb.CacheSidechainHashToAck(strSChash);

    return NullUniValue;

}

UniValue nacksidechain(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
            "nacksidechain\n"
            "nacksidechain sidechain proposals\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("nacksidechain", "")
            + HelpExampleRpc("nacksidechain", "")
            );
    uint256 strSChash = uint256S(request.params[0].get_str());

    // See acksidechain: needs cs_main so the removal is not silently reverted.
    LOCK(cs_main);

    scdb.RemoveSidechainHashToAck(strSChash);

    return NullUniValue;

}

UniValue listhashsidechain(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listhashsidechain\n"
            "listhashsidechain sidechain proposals\n"
            "Lists the acksidechain RPC list only (not -acksidechainproposal), each hash\n"
            "BYTE-REVERSED relative to getsidechainactivationstatus \"proposalhash\".\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listhashsidechain", "")
            + HelpExampleRpc("listhashsidechain", "")
            );
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    std::vector<uint256> vHash = scdb.GetSidechainsToActivate();
    int longueur = vHash.size();  
          UniValue ret(UniValue::VARR);     
	for (int i = 0; i < longueur; i++) {

       		 UniValue obj(UniValue::VOBJ);
       		 obj.push_back(Pair("Hash" + std::to_string(i) + ": ", HexStr(vHash[i])));

       		 ret.push_back(obj);
    }


    return ret;

}

UniValue getsidechainactivationstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getsidechainactivationstatus\n"
            "List activation status for nSidechain.\n"
            "\"proposalhash\" is the form -acksidechainproposal and acksidechain take\n"
            "(listhashsidechain prints the same hash byte-reversed).\n"
            "\"ackedbysetting\" is true if -acksidechainproposal names the proposal;\n"
            "\"minerack\" is true if a block this node builds now acks it (for any reason:\n"
            "-acksidechainproposal, the acksidechain list, or -activatesidechains).\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("getsidechainactivationstatus", "")
            + HelpExampleRpc("getsidechainactivationstatus", "")
            );

    std::vector<SidechainActivationStatus> vStatus;
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    vStatus = scdb.GetSidechainActivationStatus();

    UniValue ret(UniValue::VARR);
    for (const SidechainActivationStatus& s : vStatus) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.proposal.title));
        obj.push_back(Pair("description", s.proposal.description));
        obj.push_back(Pair("nage", s.nAge));
        obj.push_back(Pair("nfail", s.nFail));
        obj.push_back(Pair("proposalhash", s.proposal.GetSerHash().ToString()));
        obj.push_back(Pair("ackedbysetting", IsConfiguredSidechainProposalAck(s.proposal.GetSerHash())));
        obj.push_back(Pair("minerack", MinerAcksSidechainProposal(s.proposal.GetSerHash())));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listsidechainproposalacks(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listsidechainproposalacks\n"
            "Diagnostic for -acksidechainproposal: one entry per configured value, saying\n"
            "what it matches right now. No consensus effect.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"hash\" : \"hex\",          (string) the configured value\n"
            "    \"status\" : \"s\",          (string) \"pending\" (a pending proposal: the miner acks it),\n"
            "                               \"active\" (that sidechain has activated: nothing left to ack),\n"
            "                               \"reversed\" (matches nothing, but the byte-reversed form is a\n"
            "                               pending proposal - the listhashsidechain byte order was given),\n"
            "                               \"nomatch\" (matches no pending proposal and no active sidechain)\n"
            "    \"proposalhash\" : \"hex\",  (string, \"reversed\" only) the value that should have been given\n"
            "  }, ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechainproposalacks", "")
            + HelpExampleRpc("listsidechainproposalacks", "")
            );

    LOCK(cs_main);
    UniValue ret(UniValue::VARR);
    for (const ConfiguredSidechainAckStatus& st : GetConfiguredSidechainProposalAckStatus()) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("hash", st.hash.ToString()));
        obj.push_back(Pair("status", ConfiguredSidechainAckStatusName(st.status)));
        if (st.status == ConfiguredSidechainAckStatus::REVERSED)
            obj.push_back(Pair("proposalhash", st.hashMatch.ToString()));
        ret.push_back(obj);
    }
    return ret;
}

UniValue createsidechainproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 6)
        throw std::runtime_error(
            "createsidechainproposal\n"
            "Generates a sidechain proposal to be included in the next block " \
            "mined by this node.\n"\
            "Note that this will not broadcast the proposal to other nodes. " \
            "You must mine a block which includes your proposal to complete " \
            "the process.\n"\
            "Pending proposals created by this node will automatically be " \
            "included in the soonest block mined possible.\n"
            "\nArguments:\n"
            "1. \"nsidechain\"   (numeric, required) sidechain slot number\n"
            "2. \"title\"        (string, required) sidechain title\n"
            "3. \"description\"  (string, optional) sidechain description\n"
            "4. \"version\"      (numeric, optional) sidechain / proposal version\n"
            "5. \"hashid1\"      (string, optional) 256 bits used to identify sidechain\n"
            "6. \"hashid2\"      (string, optional) 160 bits used to identify sidechain\n"
            "\nExamples:\n"
            + HelpExampleCli("createsidechainproposal", "1 \"Namecoin\" \"Namecoin as a Bitcoin sidechain\" 0 78b140259d5626e17c4bf339c23cb4fa8d16d138f71d9803ec394bb01c051f0b 90869d013db27608c7428251c6755e5a1d9e9313")
            + "\n"
            + HelpExampleRpc("createsidechainproposal", "1 \"Namecoin\" \"Namecoin as a Bitcoin sidechain\" 0 78b140259d5626e17c4bf339c23cb4fa8d16d138f71d9803ec394bb01c051f0b 90869d013db27608c7428251c6755e5a1d9e9313")
            );

    int nSidechain = request.params[0].get_int();
    if (nSidechain < 0 || nSidechain > 255)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    std::string strTitle = request.params[1].get_str();

    std::string strDescription = "";
    if (!request.params[2].isNull())
        strDescription = request.params[2].get_str();

    int nVersion = -1;
    if (!request.params[3].isNull())
        nVersion = request.params[3].get_int();

    std::string strHashID1 = "";
    std::string strHashID2 = "";
    if (!request.params[4].isNull()) {
        strHashID1 = request.params[4].get_str();
        if (strHashID1.size() != 64)
            throw JSONRPCError(RPC_MISC_ERROR, "HashID1 size invalid!");
    }
    if (!request.params[5].isNull()) {
        strHashID2 = request.params[5].get_str();
        if (strHashID2.size() != 40)
            throw JSONRPCError(RPC_MISC_ERROR, "HashID2 size invalid!");
    }

    if (strTitle.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Sidechain must have a title!");

    Sidechain proposal;
    proposal.nSidechain = nSidechain;
    proposal.title = strTitle;
    proposal.description = strDescription;
    if (nVersion >= 0)
        proposal.nVersion = nVersion;
    else
        proposal.nVersion = 0;
    if (!strHashID1.empty())
        proposal.hashID1 = uint256S(strHashID1);
    if (!strHashID2.empty())
        proposal.hashID2 = uint160S(strHashID2);

    // Cache proposal so that it can be added to the next block we mine.
    // cs_main: block connection republishes the SCDB wholesale, so an unlocked
    // write here can vanish even though this call reported success.
    LOCK(cs_main);

    scdb.CacheSidechainProposals(std::vector<Sidechain>{proposal});

    // Cache the hash of the sidechain to ACK it
    scdb.CacheSidechainHashToAck(proposal.GetSerHash());

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("nSidechain", proposal.nSidechain));
    obj.push_back(Pair("title", proposal.title));
    obj.push_back(Pair("description", proposal.description));
    obj.push_back(Pair("version", proposal.nVersion));
    obj.push_back(Pair("hashID1", proposal.hashID1.ToString()));
    obj.push_back(Pair("hashID2", proposal.hashID2.ToString()));

    return obj;
}

UniValue setwithdrawalvote(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "setwithdrawalvote\n"
            "Set custom vote for sidechain Withdrawal.\n"
            "\nArguments:\n"
            "1. vote (\"upvote\"/\"downvote\"/\"abstain\")  (string, required) Vote\n"
            "2. nsidechain                            (numeric, required) Sidechain number of Withdrawal\n"
            "3. hash                                  (string, optional) Hash of the withdrawal\n"
            "\nExamples:\n"
            + HelpExampleCli("setwithdrawalvote", "")
            + HelpExampleRpc("setwithdrawalvote", "")
            );

    std::string strVote = request.params[0].get_str();
    if (strVote != "upvote" && strVote != "downvote" && strVote != "abstain")
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid vote (must be \"upvote\", \"downvote\" or \"abstain\")");

    // nSidechain
    int nSidechain = request.params[1].get_int();

    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // Vote state lives in the SCDB, which block connection republishes
    // wholesale; without cs_main a vote set here can be silently reverted.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    if (strVote == "upvote" && request.params.size() != 3)
        throw JSONRPCError(RPC_TYPE_ERROR, "Withdrawal hash required for upvote");

    std::string strHash = "";
    if (request.params.size() == 3) {
        strHash = request.params[2].get_str();
        if (strHash.size() != 64)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");
    }

    uint256 hash = uint256S(strHash);
    if (request.params.size() == 3 && hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    // Get current votes
    std::vector<std::string> vVote = scdb.GetVotes();

    if (strVote == "upvote")
        vVote[nSidechain] = strHash;
    else
    if (strVote == "downvote")
        vVote[nSidechain] = SCDB_DOWNVOTE;
    else
    if (strVote == "abstain")
        vVote[nSidechain] = SCDB_ABSTAIN;

    if (!scdb.CacheCustomVotes(vVote))
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to cache withdrawal votes!");

    return NullUniValue;
}

UniValue clearwithdrawalvotes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "clearwithdrawalvotes\n"
            "Delete all custom Withdrawal vote(s).\n"
            "\nExamples:\n"
            + HelpExampleCli("clearwithdrawalvotes", "")
            + HelpExampleRpc("clearwithdrawalvotes", "")
            );

    // See setwithdrawalvote: the SCDB is republished wholesale on block
    // connection, so this reset needs cs_main to not be silently undone.
    LOCK(cs_main);

    scdb.ResetWithdrawalVotes();

    return NullUniValue;
}

UniValue listwithdrawalvotes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listwithdrawalvotes\n"
            "List custom votes for sidechain Withdrawal(s).\n"
            "\nExamples:\n"
            + HelpExampleCli("listwithdrawalvotes", "")
            + HelpExampleRpc("listwithdrawalvotes", "")
            );

    UniValue ret(UniValue::VARR);

    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    std::vector<std::string> vVote = scdb.GetVotes();
    // Index with size_t: vVote holds SIDECHAIN_ACTIVATION_MAX_ACTIVE (256)
    // entries, which a uint8_t counter cannot represent as a bound.
    for (size_t i = 0; i < vVote.size(); i++) {
        std::string strVote = "";
        if (vVote[i].size() == 64)
            strVote = vVote[i];
        else
        if (vVote[i].front() == SCDB_DOWNVOTE)
            strVote = "Downvote";
        else
        if (vVote[i].front() == SCDB_ABSTAIN)
            strVote = "Abstain";

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("nSidechain", (int)i));
        obj.push_back(Pair("vote", strVote));
        ret.push_back(obj);
    }

    return ret;
}

UniValue getaveragefee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "getaveragefee\n"
            "\nArguments:\n"
            "1. block_count     (numeric, optional, default=6) number of blocks to scan\n"
            "2. start_height    (numeric, optional, default=current block count) block height to start from\n"
            "\nResult:\n"
            "{\n"
            "  \"fee\" : x.x,   (numeric) average of fees in " + CURRENCY_UNIT + "/kB\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getaveragefee", "6 10")
            );

    int nBlocks = 6;
    if (request.params.size() >= 1)
        nBlocks = request.params[0].get_int();

    // Security fix: a negative block_count passes the "> nHeight" guard below,
    // makes the loop body never run, and leaves nTx == 0 -> division by zero
    // (SIGFPE) at the end. Reject it up front.
    if (nBlocks < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid number of blocks!");

    // Security fix (node stall): the scan loop below reads each block from disk
    // while holding cs_main (taken next). Bound the number of blocks so a large
    // caller-supplied block_count cannot hold cs_main across an unbounded disk
    // read and freeze the node. 2016 (one retarget period) is ample for a fee
    // average.
    static const int MAX_AVERAGE_FEE_BLOCKS = 2016;
    if (nBlocks > MAX_AVERAGE_FEE_BLOCKS)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many blocks requested!");

    // Security fix (reorg-race crash): hold cs_main across all reads of
    // chainActive / mapBlockIndex below. Without it a concurrent reorg can
    // shrink chainActive between the height read and the indexed access,
    // making chainActive[i] return null and crashing the node.
    LOCK(cs_main);

    int nHeight = chainActive.Height();
    if (request.params.size() == 2) {
        int nHeightIn = request.params[1].get_int();
        if (nHeightIn < 0 || nHeightIn > nHeight)
            throw JSONRPCError(RPC_MISC_ERROR, "Invalid start height!");

        nHeight = nHeightIn;
    }

    // Guard the no-blocks case (empty chain) so chainActive[i] is never
    // dereferenced with a negative index below.
    if (nHeight < 0)
        throw JSONRPCError(RPC_MISC_ERROR, "Chain has no blocks!");

    if (nBlocks > nHeight)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid number of blocks!");

    int nTx = 0;
    CAmount nTotalFees = 0;
    for (int i = nHeight; i >= (nHeight - nBlocks); i--) {
        uint256 hashBlock = chainActive[i]->GetBlockHash();

        if (mapBlockIndex.count(hashBlock) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlock block;
        CBlockIndex* pblockindex = mapBlockIndex[hashBlock];
        if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
            throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
            throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");

        // We don't have the coins (they are spent) to look up the transaction
        // input amounts for calculation of fees. Instead, get the block subsidy
        // for the height and subtract it from the coinbase output amount to
        // estimate fees paid in the block.
        CAmount nSubsidy = GetBlockSubsidy(i, Params().GetConsensus());
        CAmount nCoinbase = block.vtx[0]->GetValueOut();

        // Record total fees in the block. Check-before-add: each coinbase is
        // <= MAX_MONEY, but MAX_MONEY is ~98.7% of INT64_MAX here, so summing
        // across blocks could overflow int64 (UB). Guard the positive case.
        const CAmount nDelta = nCoinbase - nSubsidy;
        if (nDelta > 0 && nTotalFees > MAX_MONEY - nDelta)
            throw JSONRPCError(RPC_MISC_ERROR, "Accumulated fee total out of range!");
        nTotalFees += nDelta;
        // Record number of transactions
        nTx += block.vtx.size();
    }

    // Belt-and-braces: nTx is >= 1 here (the loop runs at least once and every
    // block has a coinbase), but guard the division anyway - integer div-by-zero
    // is a SIGFPE process crash.
    if (nTx == 0)
        throw JSONRPCError(RPC_MISC_ERROR, "No transactions in scanned range!");

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("feeaverage", ValueFromAmount(nTotalFees / nTx)));
    return result;
}

UniValue getworkscore(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "getworkscore \"nsidechain\" \"hash\")\n"
            "Request the workscore of a Withdrawal\n"
            "\nArguments:\n"
            "1. nsidechain     (numeric, required) Sidechain number to look up Withdrawal of\n"
            "2. hash           (string, required) Hash of the Withdrawal\n"
            "\nResult:\n"
            "{\n"
            "  \"workscore\" : x,   (numeric) workscore of Withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getworkscore", "0 hash")
            );

    // nSidechain
    int nSidechain = request.params[0].get_int();

    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    std::string strHash = request.params[1].get_str();
    if (strHash.size() != 64)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");

    uint256 hash = uint256S(strHash);
    if (hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    std::vector<SidechainWithdrawalState> vState = scdb.GetState(nSidechain);
    if (vState.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "No Withdrawal(s) in SCDB for sidechain");

    int nWorkScore = -1;
    for (const SidechainWithdrawalState& s : vState) {
        if (s.hash == hash) {
            nWorkScore = s.nWorkScore;
            break;
        }
    }

    if (nWorkScore == -1)
        throw JSONRPCError(RPC_TYPE_ERROR, "No Withdrawal workscore in SCDB");

    return nWorkScore;
}

UniValue listwithdrawalstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listwithdrawalstatus \"nsidechain\")\n"
            "Request the workscore of a Withdrawal\n"
            "\nArguments:\n"
            "1. nsidechain     (numeric, required) Sidechain number to look up Withdrawal(s) of\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\" : (string) hash of Withdrawal\n"
            "  \"nblocksleft\" : x, (numeric) verification blocks remaining\n"
            "  \"workscore\" : x, (numeric) workscore of Withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getworkscore", "0 hash")
            );

    // nSidechain
    int nSidechain = request.params[0].get_int();

    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    std::vector<SidechainWithdrawalState> vState = scdb.GetState(nSidechain);

    UniValue ret(UniValue::VARR);
    for (const SidechainWithdrawalState& s : vState) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("hash", s.hash.ToString()));
        obj.push_back(Pair("nblocksleft", (int64_t)s.nBlocksLeft));
        obj.push_back(Pair("nworkscore", (int64_t)s.nWorkScore));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listcachedwithdrawaltx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "listcachedwithdrawaltx nsidechain ( verbose )\n"
            "List my cached Withdrawal(s) for nSidechain\n"
            "\nArguments:\n"
            "1. nsidechain     (numeric, required) Sidechain number to list Withdrawal(s) of\n"
            "2. verbose        (boolean, optional, default=false) Also return each bundle's raw\n"
            "                  transaction hex, as receivewithdrawalbundle takes it\n"
            "\nResult: (array)\n"
            "{\n"
            "  \"hash\" : x (string) hash of Withdrawal\n"
            "  \"hex\" : x  (string) raw bundle hex (only with verbose=true)\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listcachedwithdrawaltransactions", "0")
            );

    // nSidechain
    int nSidechain = request.params[0].get_int();

    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");
    const bool fVerbose = request.params.size() > 1 && !request.params[1].isNull() && request.params[1].get_bool();
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    std::vector<std::pair<uint8_t, CMutableTransaction>> vWithdrawal;
    vWithdrawal = scdb.GetWithdrawalTxCache();

    if (vWithdrawal.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "No withdrawal bundle txns cached for sidechain");

    UniValue ret(UniValue::VARR);
    for (auto const& i : vWithdrawal) {
        if (i.first != nSidechain)
            continue;

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("hash", i.second.GetHash().ToString()));
        // 0.45.2: the bytes, so an operator can keep a copy to re-submit
        // (receivewithdrawalbundle <slot> <hex>) - nothing else prints them.
        if (fVerbose)
            obj.push_back(Pair("hex", EncodeHexTx(CTransaction(i.second))));

        ret.push_back(obj);
    }

    return ret;
}

UniValue havespentwithdrawal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "havespentwithdrawal\n"
            "Return whether this Withdrawal was spent\n"
            "\nResult: true | false \n"
            "\nExample:\n"
            + HelpExampleCli("havespentwithdrawal", "hash, nsidechain")
            );

    std::string strHash = request.params[0].get_str();
    if (strHash.size() != 64)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");

    uint256 hash = uint256S(strHash);
    if (hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    int nSidechain = request.params[1].get_int();

    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    bool fSpent = scdb.HaveSpentWithdrawal(hash, nSidechain);

    return fSpent;
}

UniValue havefailedwithdrawal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "havefailedwithdrawal\n"
            "Return whether this Withdrawal failed\n"
            "\nResult: true | false \n"
            "\nExample:\n"
            + HelpExampleCli("havefailedwithdrawal", "hash, nsidechain")
            );

    std::string strHash = request.params[0].get_str();
    if (strHash.size() != 64)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");

    uint256 hash = uint256S(strHash);
    if (hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    int nSidechain = request.params[1].get_int();

    // Security fix: range-check the int before it is truncated to uint8_t by
    // IsSidechainActive(); an out-of-range value (e.g. 256+S) would otherwise
    // alias an active slot and later index a 256-element vector out of bounds.
    if (nSidechain < 0 || nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    bool fFailed = scdb.HaveFailedWithdrawal(hash, nSidechain);

    return fFailed;
}

UniValue listspentwithdrawals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "listspentwithdrawals\n"
            "List Withdrawal(s) which have been approved by workscore and spent\n"
            "\nResult: (array)\n"
            "{\n"
            "  \"nsidechain\" : (numeric) Sidechain number of Withdrawal\n"
            "  \"hash\" : (string) hash of Withdrawal\n"
            "  \"hashblock\"   : (string) hash of block Withdrawal was spent in\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listspentwithdrawals", "")
            );

    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    std::vector<SidechainSpentWithdrawal> vSpent = scdb.GetSpentWithdrawalCache();

    UniValue ret(UniValue::VARR);
    for (const SidechainSpentWithdrawal& s : vSpent) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("nsidechain", s.nSidechain));
        obj.push_back(Pair("hash", s.hash.ToString()));
        obj.push_back(Pair("hashblock", s.hashBlock.ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listfailedwithdrawals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "listfailedwithdrawals\n"
            "List Withdrawal(s) which have failed\n"
            "\nResult: (array)\n"
            "{\n"
            "  \"nsidechain\" : (numeric) Sidechain number of Withdrawal\n"
            "  \"hash\" : (string) hash of withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listfailedwithdrawals", "")
            );

    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    std::vector<SidechainFailedWithdrawal> vFailed = scdb.GetFailedWithdrawalCache();

    UniValue ret(UniValue::VARR);
    for (const SidechainFailedWithdrawal& f : vFailed) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("nsidechain", f.nSidechain));
        obj.push_back(Pair("hash", f.hash.ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue gettotalscdbhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "gettotalscdbhash\n"
            "Get hash of every member of SCDB combined.\n"
            );

    UniValue ret(UniValue::VOBJ);
    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    ret.push_back(Pair("hashscdbtotal", scdb.GetTestHash(chainActive.Height()).ToString()));

    return ret;
}

UniValue getscdbdataforblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getscdbdataforblock\n"
            "Get SCDB data from leveldb for the specified block hash\n"
            "\nResult:\n"
            "\"nsidechains\" : (numeric) Number of active sidechains\n"
            "\nArray of Withdrawal status\n"
            "{\n"
            "  \"nsidechain\"  : (numeric) Sidechain number of Withdrawal\n"
            "  \"nblocksleft\" : (numeric) Blocks remaining to validate Withdrawal\n"
            "  \"nworkscore\"  : (numeric) Number of ACK(s) Withdrawal has received\n"
            "  \"hash\" : (string) hash of withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getscdbdataforblock", "hashblock")
            );


    uint256 hashBlock = uint256S(request.params[0].get_str());

    LOCK(cs_main);

    BlockMap::iterator it = mapBlockIndex.find(hashBlock);
    if (it == mapBlockIndex.end()) {
        std::string strError = "Block hash not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlockIndex* pblockindex = it->second;
    if (pblockindex == NULL) {
        std::string strError = "Block index null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    SidechainBlockData data;
    if (!psidechaintree->GetBlockData(hashBlock, data))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't find data for block.");

    UniValue ret(UniValue::VARR);
    UniValue obj(UniValue::VOBJ);
    ret.push_back(obj);
    for (auto& x : data.vWithdrawalStatus) {
        for (auto& y : x) {
            UniValue obj(UniValue::VOBJ);
            obj.push_back(Pair("nsidechain", y.nSidechain));
            obj.push_back(Pair("nblocksleft", (int64_t)y.nBlocksLeft));
            obj.push_back(Pair("nworkscore", (int64_t)y.nWorkScore));
            obj.push_back(Pair("withdrawalbundle", y.hash.ToString()));
            ret.push_back(obj);
        }
    }

    // TODO print vActivationStatus
    // TODO print vSidechain

    return ret;
}

UniValue listfailedbmm(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "listfailedbmm\n"
            "Print the list of failed BMM transactions yet to be abandoned.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\" : (string) Failed BMM txid.\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listfailedbmm", "")
            );

    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    std::set<uint256> setTxid = scdb.GetRemovedBMM();

    UniValue ret(UniValue::VARR);
    for (const uint256& u : setTxid) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txid", u.ToString()));
        ret.push_back(obj);
    }

    return ret;
}

//! Bounds on a user-created news topic. The day count matches the maximum the
//! interface's own spin box allows, so a topic made here cannot be one the
//! interface would refuse to make.
static const int MAX_NEWS_TYPE_DAYS = 1337;
static const size_t MAX_NEWS_TYPE_TITLE_CHARS = 128;

//! Ceiling on how much listnews will assemble in memory for one call.
static const size_t MAX_LISTNEWS_RESULT_BYTES = 8 * 1024 * 1024;

//! Render an OP_RETURN payload as text for a JSON reply.
//!
//! The bytes are arbitrary and mostly are not text at all - every block carries
//! a segwit commitment, which is an OP_RETURN full of binary - so copying them
//! into a JSON string produces a reply the client cannot parse. That is not
//! hypothetical: getopreturndata failed with "couldn't parse reply from server"
//! on any ordinary block, which is nearly all of them. Keep the printable
//! characters and drop the rest; the untouched bytes are in the hex field
//! alongside for anything that needs them. SAFE_CHARS_DEFAULT is the widest of
//! the available sets, so ordinary prose survives it intact.
static std::string DecodeOPReturnText(const CScript& script)
{
    std::string strRaw;
    for (const unsigned char& c : script)
        strRaw += c;

    // Keep printable ASCII and drop everything else. SanitizeString's widest
    // set is narrower than it sounds - it discards apostrophes, quotes and
    // most punctuation - which mangles ordinary prose. Bytes 0x20 to 0x7e are
    // the whole printable range, and univalue escapes the quote and backslash
    // among them correctly, so this is safe to put in a JSON string while
    // keeping the text readable.
    //
    // Anything above 0x7f is dropped rather than passed through: univalue's
    // writer emits high bytes raw, so a payload that is not valid UTF-8 would
    // produce a reply the client cannot parse - which is the bug this function
    // exists to fix. That means non-ASCII text does not survive here; the
    // untouched bytes are in the hex field alongside.
    std::string strOut;
    strOut.reserve(strRaw.size());
    for (const unsigned char c : strRaw) {
        if (c >= 0x20 && c <= 0x7e)
            strOut += (char)c;
    }
    return strOut;
}

//! The two topics the interface ships with. They are not stored in the news
//! type database - the GUI holds them in a static list - so they are repeated
//! here to give a command-line user the same starting set. Keep in step with
//! vDefaultType in qt/newstypestablemodel.cpp.
static const struct { const char* header; const char* title; int nDays; } vBuiltinNewsType[] = {
    { "a1a1a1a1", "Daily Doge", 7 },
    { "a2a2a2a2", "Doge Extra", 7 },
};

UniValue listnewstypes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listnewstypes\n"
            "\nList the news topics this node knows, built in and user created.\n"
            "\nThe header bytes are what broadcastnews takes as its first argument.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"title\"    : (string) topic name\n"
            "    \"header\"   : (string) header bytes, as hex\n"
            "    \"days\"     : (numeric) length of the ranking period in days\n"
            "    \"builtin\"  : (boolean) true if it ships with the wallet\n"
            "    \"hash\"     : (string) identifier for removenewstype (user topics only)\n"
            "    \"url\"      : (string) shareable topic string (user topics only)\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listnewstypes", "")
            + HelpExampleRpc("listnewstypes", "")
            );

    UniValue ret(UniValue::VARR);

    for (const auto& t : vBuiltinNewsType) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", t.title));
        obj.push_back(Pair("header", t.header));
        obj.push_back(Pair("days", t.nDays));
        obj.push_back(Pair("builtin", true));
        ret.push_back(obj);
    }

    std::vector<NewsType> vType;
    popreturndb->GetNewsTypes(vType);
    for (const NewsType& type : vType) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", type.title));
        obj.push_back(Pair("header", HexStr(type.header.begin(), type.header.end())));
        obj.push_back(Pair("days", type.nDays));
        obj.push_back(Pair("builtin", false));
        obj.push_back(Pair("hash", type.GetHash().ToString()));
        obj.push_back(Pair("url", type.GetShareURL()));
        ret.push_back(obj);
    }

    return ret;
}

UniValue createnewstype(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "createnewstype \"title\" \"header\" days\n"
            "\nAdd a news topic to this node. Local only - a topic is a label for\n"
            "header bytes, and nothing about it is broadcast. Others see the same\n"
            "posts once they add a topic with the same header.\n"
            "\nArguments:\n"
            "1. \"title\"   (string, required) name to display\n"
            "2. \"header\"  (string, required) 4 header bytes as 8 hex characters (ex: a1a1a1a1)\n"
            "3. days      (numeric, required) length of the ranking period, 1 or more\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\" : (string) identifier for removenewstype\n"
            "  \"url\"  : (string) shareable topic string\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("createnewstype", "\"My Topic\" \"a3a3a3a3\" 7")
            + HelpExampleRpc("createnewstype", "\"My Topic\", \"a3a3a3a3\", 7")
            );

    const std::string strTitle = request.params[0].get_str();
    if (strTitle.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Title cannot be empty");
    // Bounded because the topic is written to disk and displayed; nothing
    // rejects a multi-megabyte one otherwise, and it would be permanent.
    if (strTitle.size() > MAX_NEWS_TYPE_TITLE_CHARS)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Title must be %u characters or fewer", MAX_NEWS_TYPE_TITLE_CHARS));

    const std::string strHeader = request.params[1].get_str();
    // Matches what broadcastnews accepts, so a topic created here can always be
    // posted to.
    if (strHeader.size() != 8 || !IsHex(strHeader))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Header must be 8 hex characters (4 bytes)");

    const int nDays = request.params[2].get_int();
    // The upper bound is the one the interface already enforces on this field,
    // and it is not cosmetic. The news table walks back from the tip until it
    // reaches tip time minus nDays; a huge value makes that QDateTime invalid,
    // the stop condition never fires, and the walk runs to the genesis block -
    // a database read per block, on the GUI thread, holding cs_main. Writing a
    // topic through this command must not be able to wedge a wallet that later
    // views it.
    if (nDays < 1 || nDays > MAX_NEWS_TYPE_DAYS)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Days must be between 1 and %d", MAX_NEWS_TYPE_DAYS));

    NewsType type;
    type.title = strTitle;
    type.nDays = nDays;
    const std::vector<unsigned char> vBytes = ParseHex(strHeader);
    type.header = CScript(vBytes.begin(), vBytes.end());

    popreturndb->WriteNewsType(type);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("hash", type.GetHash().ToString()));
    obj.push_back(Pair("url", type.GetShareURL()));
    return obj;
}

UniValue removenewstype(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "removenewstype \"hash\"\n"
            "\nRemove a user created news topic from this node. Built in topics\n"
            "cannot be removed. Posts already on the chain are unaffected.\n"
            "\nArguments:\n"
            "1. \"hash\"  (string, required) topic identifier from listnewstypes\n"
            "\nExamples:\n"
            + HelpExampleCli("removenewstype", "\"<hash>\"")
            + HelpExampleRpc("removenewstype", "\"<hash>\"")
            );

    const std::string strHash = request.params[0].get_str();
    if (strHash.size() != 64 || !IsHex(strHash))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid topic hash");

    const uint256 hash = uint256S(strHash);

    // Report a hash that matches nothing rather than silently succeeding.
    std::vector<NewsType> vType;
    popreturndb->GetNewsTypes(vType);
    bool fFound = false;
    for (const NewsType& type : vType) {
        if (type.GetHash() == hash) {
            fFound = true;
            break;
        }
    }
    if (!fFound)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No user created topic with that hash");

    popreturndb->EraseNewsType(hash);

    return NullUniValue;
}

UniValue listnews(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "listnews ( count \"header\" )\n"
            "\nList OP_RETURN posts from recent blocks, newest block first.\n"
            "\nArguments:\n"
            "1. count     (numeric, optional, default=100) how many blocks back to read, 1 to 10000\n"
            "2. \"header\"  (string, optional) only return posts whose data starts with\n"
            "               these header bytes, as hex. Omit for every post.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"blockhash\" : (string) block containing the post\n"
            "    \"height\"    : (numeric) height of that block\n"
            "    \"txid\"      : (string) transaction id\n"
            "    \"fees\"      : (string) fee paid, which is the post's bid\n"
            "    \"size\"      : (numeric) transaction size\n"
            "    \"hex\"       : (string) the output script data, as hex\n"
            "    \"decode\"    : (string) that data as text\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listnews", "50")
            + HelpExampleCli("listnews", "1000 \"a1a1a1a1\"")
            + HelpExampleRpc("listnews", "50, \"a1a1a1a1\"")
            );

    int nCount = 100;
    if (request.params.size() > 0) {
        nCount = request.params[0].get_int();
        // Bounded because each block read is a database lookup and the result
        // is assembled in memory before it is returned.
        if (nCount < 1 || nCount > 10000)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Count must be between 1 and 10000");
    }

    std::vector<unsigned char> vFilter;
    if (request.params.size() > 1) {
        const std::string strHeader = request.params[1].get_str();
        if (strHeader.empty() || (strHeader.size() % 2) != 0 || !IsHex(strHeader))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Header must be an even number of hex characters");
        vFilter = ParseHex(strHeader);
    }

    // Take the block hashes under cs_main and let go of it before touching the
    // database. Holding it across the reads would stall block connection, the
    // network threads and getblocktemplate for as long as they take, and they
    // are not cheap: the OP_RETURN index runs to hundreds of megabytes on
    // mainnet and is opened with a 500-byte cache (nOPReturnCache), so every
    // lookup goes to the operating system or the disk. Ten thousand of those
    // is seconds on an SSD and considerably worse on a spinning disk.
    //
    // A reorg between the snapshot and the reads is harmless. Block hashes are
    // immutable, so the worst case is a row describing a block that has just
    // left the active chain - stale, not wrong - and the hash is reported in
    // the row, so a caller can tell.
    std::vector<std::pair<uint256, int>> vBlock;
    {
        LOCK(cs_main);

        const CBlockIndex* pindex = chainActive.Tip();
        for (int i = 0; i < nCount && pindex != nullptr; i++, pindex = pindex->pprev)
            vBlock.emplace_back(pindex->GetBlockHash(), pindex->nHeight);
    }

    UniValue ret(UniValue::VARR);
    size_t nBytes = 0;

    for (const std::pair<uint256, int>& block : vBlock) {
        std::vector<OPReturnData> vData;
        if (!popreturndb->GetBlockData(block.first, vData))
            continue;

        for (const OPReturnData& d : vData) {
            // d.script is the whole output script, so the header sits one byte
            // in, past OP_RETURN.
            if (!vFilter.empty()) {
                if (d.script.size() < vFilter.size() + 1)
                    continue;
                if (!std::equal(vFilter.begin(), vFilter.end(), d.script.begin() + 1))
                    continue;
            }

            // The count bounds blocks read, not data returned, and there is no
            // per-block ceiling on how much OP_RETURN a block may carry - a
            // single output may hold MAX_DRIVECHAIN_DATA_BYTES and a block may
            // hold many. Left unbounded, one call on a chain carrying real
            // payloads assembles gigabytes here before anything is sent. Fail
            // loudly instead of truncating, so a caller is never quietly handed
            // a partial answer it might read as the whole of the news.
            nBytes += d.script.size() * 3 + 256;
            if (nBytes > MAX_LISTNEWS_RESULT_BYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Result exceeds %u bytes. Ask for fewer blocks, or narrow it with the header argument.",
                              MAX_LISTNEWS_RESULT_BYTES));
            }

            UniValue obj(UniValue::VOBJ);
            obj.push_back(Pair("blockhash", block.first.ToString()));
            obj.push_back(Pair("height", block.second));
            obj.push_back(Pair("txid", d.txid.ToString()));
            obj.push_back(Pair("fees", FormatMoney(d.fees)));
            obj.push_back(Pair("size", (uint64_t)d.nSize));
            obj.push_back(Pair("hex", HexStr(d.script.begin(), d.script.end(), false)));

            obj.push_back(Pair("decode", DecodeOPReturnText(d.script)));

            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue getopreturndata(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getopreturndata\n"
            "Print OP_RETURN data for block.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\"   : (string) transaction id\n"
            "  \"size\"   : (numeric) transaction size.\n"
            "  \"fees\"   : (numeric) transaction fees.\n"
            "  \"hex\"    : (string) hex from output.\n"
            "  \"decode\" : (string) decoded hex.\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getopreturndata", "")
            );

    uint256 hashBlock = uint256S(request.params[0].get_str());

    LOCK(cs_main);

    BlockMap::iterator it = mapBlockIndex.find(hashBlock);
    if (it == mapBlockIndex.end()) {
        std::string strError = "Block hash not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlockIndex* pblockindex = it->second;
    if (pblockindex == NULL) {
        std::string strError = "Block index null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    std::vector<OPReturnData> vData;
    if (!popreturndb->GetBlockData(hashBlock, vData))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't find data for block.");

    UniValue ret(UniValue::VARR);
    for (const OPReturnData& d : vData) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txid", d.txid.ToString()));
        obj.push_back(Pair("size", (uint64_t)d.nSize));
        obj.push_back(Pair("fees", FormatMoney(d.fees)));
        obj.push_back(Pair("hex", HexStr(d.script.begin(), d.script.end(), false)));

        obj.push_back(Pair("decode", DecodeOPReturnText(d.script)));

        ret.push_back(obj);
    }

    return ret;
}

UniValue getactivesidechaincount(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "getactivesidechaincount\n"
            "Count number of active sidechains.\n"
            "\nResult:\n"
            "{\n"
            "  \"count\"   : (number) number of active sidechains\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getactivesidechaincount", "")
            );

    // The global scdb is move-assigned wholesale by ConnectBlock under
    // cs_main, so reading it without that lock can walk a container that is
    // being replaced. Read-only here, and no wallet sync call intervenes, so
    // the lock spans the rest of the function.
    LOCK(cs_main);

    int count = scdb.GetActiveSidechainCount();

    return count;
}

//! Append the consensus-container fields shared by getscdbhash and
//! getscdbstate.
//!
//! The commands' existing fields read the process-global SCDB and their
//! meaning is frozen: archived census readings and upgrade checks compare
//! them across binaries, so a redefinition would silently compare two
//! different containers while both agree on every healthy node. Everything
//! the consensus container has to say is therefore reported through these
//! ADDITIVE fields; an older binary simply lacks them, which a census must
//! read as "instrument not fitted", never as agreement.
//!
//! Requires cs_main.
static void PushSCDBValidationFields(UniValue& obj, const CBlockIndex* pTip,
        const uint256& hashGlobalConsensus, const uint256& hashGlobalCommitment)
{
    AssertLockHeld(cs_main);

    // The container ConnectBlock actually validates the next block against:
    // the global with the tip's per-block record overlaid where that record
    // is complete. Same construction, same helper, as ConnectBlock and the
    // miner use - a reading assembled from any other container reports a
    // state consensus never consults.
    SidechainDB scdbValidation = GetSCDBConsensusSeed(pTip, Params().GetConsensus());
    const uint256 hashValidationConsensus = scdbValidation.GetConsensusHash(pTip ? pTip->nHeight : 0);
    const uint256 hashValidationCommitment = scdbValidation.GetCommitmentHash(pTip ? pTip->nHeight : 0);

    obj.push_back(Pair("validationconsensushash", hashValidationConsensus.ToString()));
    obj.push_back(Pair("validationcommitmenthash", hashValidationCommitment.ToString()));
    obj.push_back(Pair("validationblockhash", scdbValidation.GetHashBlockLastSeen().ToString()));

    // The one boolean the census wants: does the in-memory global agree with
    // the container consensus reads? False while insync is false merely
    // restates staleness; false while insync is true is drift - the global
    // holds validity-relevant state the record chain does not.
    obj.push_back(Pair("validationmatch",
            hashValidationConsensus == hashGlobalConsensus &&
            hashValidationCommitment == hashGlobalCommitment));

    // Whether this node's own caches are sound enough for it to be used as a
    // census reference, COMPUTED ON DEMAND rather than latched.
    //
    // ConnectBlock logs and alerts when it notices either condition, but a log
    // line and an -alertnotify are one-shot: they cannot say the node has since
    // been repaired. A sticky global warning is worse than useless here for the
    // same reason - rebuildscdb never clears it, so a repaired node keeps
    // claiming to be broken until it restarts, and the single shared warning
    // string means the SCDB claim can also overwrite an unrelated clock or disk
    // warning. Reading the live state is the only form that answers "is it
    // sound NOW", which is the only question a census actually asks.
    //
    // depositcachesound is the deposits-present / pointer-consistent check;
    // it CANNOT see the all-empty variant (an active slot with neither pointer
    // nor deposits), so true here is not a clean bill of health on its own.
    // treasurylogsound is the internal mapCTIP/mapTreasury invariant, which
    // should never be false on any build.
    uint8_t nSlotUnsupported = 0;
    const bool fDepositCacheSound = scdb.DepositCacheSupportsTreasury(nSlotUnsupported);
    obj.push_back(Pair("depositcachesound", fDepositCacheSound));
    if (!fDepositCacheSound)
        obj.push_back(Pair("depositcacheunsoundslot", (int)nSlotUnsupported));

    SidechainDB::TreasuryLogAudit audit;
    scdb.GetTreasuryLog(&audit);
    obj.push_back(Pair("treasurylogsound", audit.IsClean()));
    if (!audit.IsClean()) {
        UniValue objAudit(UniValue::VOBJ);
        UniValue arrMissing(UniValue::VARR), arrStale(UniValue::VARR), arrMismatched(UniValue::VARR);
        for (const uint8_t n : audit.vMissing) arrMissing.push_back((int)n);
        for (const uint8_t n : audit.vStale) arrStale.push_back((int)n);
        for (const uint8_t n : audit.vMismatched) arrMismatched.push_back((int)n);
        objAudit.push_back(Pair("nolog", arrMissing));
        objAudit.push_back(Pair("nopointer", arrStale));
        objAudit.push_back(Pair("mismatched", arrMismatched));
        obj.push_back(Pair("treasurylogaudit", objAudit));
    }

    // What the tip's own coinbase committed, read back from the block itself.
    // From SCDBCommitmentHeight, validationcommitmenthash equals this value
    // on any node holding the chain's records - provably, not hopefully:
    // ConnectBlock computes the committed hash from the post-connect
    // scdbCache and writes the tip's record from that same state, so the
    // overlay above reproduces every hashed container. Comparing against it
    // is node-vs-chain rather than node-vs-node, which two nodes wrong in
    // the same way would pass. Empty (and the match false) whenever the tip
    // carries no commitment - every block below SCDBCommitmentHeight.
    bool fTipCommit = false;
    uint256 hashTipCommit;
    if (pTip) {
        CBlock block;
        if (ReadBlockFromDisk(block, pTip, Params().GetConsensus()) &&
                !block.vtx.empty() && block.vtx[0]) {
            // Takes the last matching output; ConnectBlock requires exactly one.
            uint256 hashOut;
            for (const CTxOut& out : block.vtx[0]->vout) {
                if (out.scriptPubKey.IsSCDBHashCommit(hashOut)) {
                    hashTipCommit = hashOut;
                    fTipCommit = true;
                }
            }
        }
    }
    obj.push_back(Pair("tipcommitment", fTipCommit ? hashTipCommit.ToString() : ""));
    obj.push_back(Pair("tipcommitmentmatch",
            fTipCommit && hashTipCommit == hashValidationCommitment));
}

UniValue getscdbhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getscdbhash\n"
            "\nHash of the sidechain database state that block validity depends on.\n"
            "\nTwo honest nodes at the same block must report the same hash. If they\n"
            "do not, they disagree about something consensus reads, and one of them\n"
            "will reject a block the other accepts - usually surfacing much later as\n"
            "a refused withdrawal payout.\n"
            "\nCompare across nodes by matching on blockhash first; a hash taken at a\n"
            "different height is not comparable.\n"
            "\nThis reports state only and changes nothing. No block carries\n"
            "consensushash; commitmenthash is the form a coinbase commits to from\n"
            "SCDBCommitmentHeight - the same state minus everything that depends\n"
            "on the committing block's own hash.\n"
            "\nTwo containers are reported. consensushash, commitmenthash and\n"
            "blockhash read the process-global SCDB, exactly as every archived\n"
            "reading of those names did. The validation* fields read the container\n"
            "block validity is actually decided against: the global with the tip's\n"
            "per-block record overlaid where that record is complete - the same\n"
            "construction ConnectBlock validates with and the miner commits to.\n"
            "On a healthy node the two agree (validationmatch true).\n"
            "\nFrom SCDBCommitmentHeight, validationcommitmenthash is exactly the\n"
            "value the tip's own coinbase committed: ConnectBlock computes the\n"
            "committed hash from the post-connect state and writes the tip's\n"
            "record from that same state, so overlaying the record reproduces it.\n"
            "tipcommitment reads that committed value back out of the tip's\n"
            "coinbase, so tipcommitmentmatch compares this node against the chain\n"
            "itself rather than against another node.\n"
            "\nResult:\n"
            "{\n"
            "  \"consensushash\"  : (string) hash of the validity-relevant state\n"
            "                      (global SCDB)\n"
            "  \"commitmenthash\" : (string) the committed form of the same state\n"
            "                      (global SCDB)\n"
            "  \"blockhash\"      : (string) the block that state describes\n"
            "  \"chaintip\"       : (string) the node's current tip\n"
            "  \"insync\"         : (boolean) whether the two above agree\n"
            "  \"testhash\"       : (string) legacy hash, includes node-local caches\n"
            "  \"validationconsensushash\"  : (string) consensushash of the container\n"
            "                                 block validity is decided against\n"
            "  \"validationcommitmenthash\" : (string) committed form of that container;\n"
            "                                 from SCDBCommitmentHeight this is what\n"
            "                                 the tip's own coinbase committed\n"
            "  \"validationblockhash\"      : (string) the block that container describes\n"
            "  \"validationmatch\"          : (boolean) global and validation container\n"
            "  \"depositcachesound\"       : (boolean) this node's deposit cache accounts for its\n"
            "                                treasury pointers. Cannot see the all-empty variant.\n"
            "  \"treasurylogsound\"        : (boolean) mapCTIP and the treasury log agree. False\n"
            "                                means this node's SCDB is internally corrupt.\n"
            "  \"tipcommitment\"            : (string) the value the tip's coinbase\n"
            "                                 committed; empty when the tip carries no\n"
            "                                 commitment (always below\n"
            "                                 SCDBCommitmentHeight)\n"
            "  \"tipcommitmentmatch\"       : (boolean) tipcommitment present and equal\n"
            "                                 to validationcommitmenthash\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getscdbhash", "")
            + HelpExampleRpc("getscdbhash", "")
            );

    LOCK(cs_main);

    const uint256 hashBlockLastSeen = scdb.GetHashBlockLastSeen();
    const CBlockIndex* pTip = chainActive.Tip();
    const uint256 hashTip = pTip ? pTip->GetBlockHash() : uint256();

    // Into locals so the validationmatch comparison below is against the very
    // values reported; the reported values themselves are unchanged.
    const uint256 hashGlobalConsensus = scdb.GetConsensusHash(chainActive.Height());
    const uint256 hashGlobalCommitment = scdb.GetCommitmentHash(chainActive.Height());

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("consensushash", hashGlobalConsensus.ToString()));
    obj.push_back(Pair("commitmenthash", hashGlobalCommitment.ToString()));
    obj.push_back(Pair("blockhash", hashBlockLastSeen.ToString()));
    obj.push_back(Pair("chaintip", hashTip.ToString()));
    // A node whose SCDB has fallen behind its own tip is already in the state
    // this command exists to detect, so say so rather than making the caller
    // compare the two strings.
    obj.push_back(Pair("insync", hashBlockLastSeen == hashTip));
    obj.push_back(Pair("testhash", scdb.GetTestHash(chainActive.Height()).ToString()));

    // Appended after every pre-existing field so archived readings stay
    // comparable position-for-position as well as name-for-name.
    PushSCDBValidationFields(obj, pTip, hashGlobalConsensus, hashGlobalCommitment);

    return obj;
}

UniValue getscdbstate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getscdbstate\n"
            "\nThe sidechain database state that block validity depends on, in full.\n"
            "\nThis is the preimage of getscdbhash. That command says whether two\n"
            "nodes agree; this one says what they disagree about. Compare the\n"
            "section hashes first to find which group differs, then compare the\n"
            "array under that name - a full diff of the whole output is rarely\n"
            "what you want.\n"
            "\nOnly comparable between nodes reporting the same blockhash.\n"
            "\nThis reports state only and changes nothing. No block carries\n"
            "consensushash; commitmenthash is the form a coinbase commits to from\n"
            "SCDBCommitmentHeight.\n"
            "\nThe hashes and the arrays below them read the process-global SCDB,\n"
            "exactly as every archived reading did. The validation* and tip*\n"
            "fields appended at the end read the container block validity is\n"
            "actually decided against - the global with the tip's per-block\n"
            "record overlaid where that record is complete. From\n"
            "SCDBCommitmentHeight, validationcommitmenthash is exactly what the\n"
            "tip's own coinbase committed (ConnectBlock computed the committed\n"
            "hash from the same post-connect state it wrote the tip's record\n"
            "from), and tipcommitment reads that value back out of the coinbase.\n"
            "See getscdbhash for the per-field description.\n"
            "\nResult:\n"
            "{\n"
            "  \"consensushash\"  : (string) merkle root of every section below\n"
            "                      (global SCDB)\n"
            "  \"commitmenthash\" : (string) the committed form of the same state\n"
            "                      (global SCDB)\n"
            "  \"blockhash\"      : (string) the block this state describes\n"
            "  \"chaintip\"       : (string) the node's current tip\n"
            "  \"insync\"         : (boolean) whether the two above agree\n"
            "  \"blocks\"         : (numeric) height of the chain tip\n"
            "  \"sections\"       : [ { \"name\", \"hash\", \"leaves\" }, ... ]\n"
            "  \"sidechains\"        : [ ... ] occupied slots only\n"
            "  \"withdrawalstatus\"  : [ ... ] bundles being voted on\n"
            "  \"activationstatus\"  : [ ... ] pending sidechain proposals\n"
            "  \"ctip\"              : [ ... ] treasury pointer per sidechain,\n"
            "                          each with viewunspent/viewamount/\n"
            "                          viewnsidechain/anchored read from the\n"
            "                          coins view. anchored false means this\n"
            "                          node's pointer is not backed by the\n"
            "                          output set - see listdrivechaincoins\n"
            "  \"failedwithdrawals\" : [ ... ]\n"
            "  \"spentwithdrawals\"  : [ ... ]\n"
            "  \"validationconsensushash\"  : (string) see getscdbhash\n"
            "  \"validationcommitmenthash\" : (string) see getscdbhash\n"
            "  \"validationblockhash\"      : (string) see getscdbhash\n"
            "  \"validationmatch\"          : (boolean) see getscdbhash\n"
            "  \"depositcachesound\"       : (boolean) this node's deposit cache accounts for its\n"
            "                                treasury pointers. Cannot see the all-empty variant.\n"
            "  \"treasurylogsound\"        : (boolean) mapCTIP and the treasury log agree. False\n"
            "                                means this node's SCDB is internally corrupt.\n"
            "  \"tipcommitment\"            : (string) see getscdbhash\n"
            "  \"tipcommitmentmatch\"       : (boolean) see getscdbhash\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getscdbstate", "")
            + HelpExampleRpc("getscdbstate", "")
            );

    LOCK(cs_main);

    const uint256 hashBlockLastSeen = scdb.GetHashBlockLastSeen();
    const CBlockIndex* pTip = chainActive.Tip();
    const uint256 hashTip = pTip ? pTip->GetBlockHash() : uint256();

    // Into locals so the validationmatch comparison below is against the very
    // values reported; the reported values themselves are unchanged.
    const uint256 hashGlobalConsensus = scdb.GetConsensusHash(chainActive.Height());
    const uint256 hashGlobalCommitment = scdb.GetCommitmentHash(chainActive.Height());

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("consensushash", hashGlobalConsensus.ToString()));
    obj.push_back(Pair("commitmenthash", hashGlobalCommitment.ToString()));
    obj.push_back(Pair("blockhash", hashBlockLastSeen.ToString()));
    obj.push_back(Pair("chaintip", hashTip.ToString()));
    obj.push_back(Pair("insync", hashBlockLastSeen == hashTip));
    obj.push_back(Pair("blocks", pTip ? pTip->nHeight : 0));

    // Section hashes come from the same leaves the consensus hash is built
    // from, so a section hash cannot agree while the hash it feeds disagrees.
    // The arrays below are a rendering of those leaves for reading; where a
    // rendering and a section hash ever disagreed, the hash would be the one
    // telling the truth.
    std::vector<SidechainDB::ConsensusSection> vSection;
    scdb.GetConsensusSections(vSection, chainActive.Height());

    UniValue sections(UniValue::VARR);
    for (const SidechainDB::ConsensusSection& section : vSection) {
        UniValue s(UniValue::VOBJ);
        s.push_back(Pair("name", section.name));
        s.push_back(Pair("hash", ComputeMerkleRoot(section.vLeaf).ToString()));
        s.push_back(Pair("leaves", (uint64_t)section.vLeaf.size()));
        sections.push_back(s);
    }
    obj.push_back(Pair("sections", sections));

    // The sidechain table is 256 fixed slots and the hash covers all of them,
    // but printing 254 empty ones buries the two that matter. A slot is
    // skipped only when it is byte-identical to a never-used slot, so anything
    // capable of changing the hash is still shown.
    UniValue sidechains(UniValue::VARR);
    const std::vector<Sidechain> vSidechain = scdb.GetSidechains();
    for (size_t i = 0; i < vSidechain.size(); i++) {
        Sidechain blank;
        blank.nSidechain = i;
        if (vSidechain[i].GetSerHash() == blank.GetSerHash())
            continue;

        UniValue s(UniValue::VOBJ);
        s.push_back(Pair("nsidechain", (int)vSidechain[i].nSidechain));
        s.push_back(Pair("active", vSidechain[i].fActive));
        s.push_back(Pair("version", vSidechain[i].nVersion));
        s.push_back(Pair("title", vSidechain[i].title));
        s.push_back(Pair("description", vSidechain[i].description));
        s.push_back(Pair("hashid1", vSidechain[i].hashID1.ToString()));
        s.push_back(Pair("hashid2", vSidechain[i].hashID2.ToString()));
        s.push_back(Pair("serhash", vSidechain[i].GetSerHash().ToString()));
        sidechains.push_back(s);
    }
    obj.push_back(Pair("sidechains", sidechains));

    UniValue withdrawals(UniValue::VARR);
    const std::vector<std::vector<SidechainWithdrawalState>> vState = scdb.GetState();
    for (size_t i = 0; i < vState.size(); i++) {
        for (const SidechainWithdrawalState& state : vState[i]) {
            UniValue s(UniValue::VOBJ);
            s.push_back(Pair("nsidechain", (int)state.nSidechain));
            s.push_back(Pair("hash", state.hash.ToString()));
            s.push_back(Pair("blocksleft", (int)state.nBlocksLeft));
            s.push_back(Pair("workscore", (int)state.nWorkScore));
            withdrawals.push_back(s);
        }
    }
    obj.push_back(Pair("withdrawalstatus", withdrawals));

    UniValue activation(UniValue::VARR);
    for (const SidechainActivationStatus& a : scdb.GetSidechainActivationStatus()) {
        UniValue s(UniValue::VOBJ);
        s.push_back(Pair("nsidechain", (int)a.proposal.nSidechain));
        s.push_back(Pair("age", a.nAge));
        s.push_back(Pair("fail", a.nFail));
        s.push_back(Pair("title", a.proposal.title));
        s.push_back(Pair("serhash", a.GetSerHash().ToString()));
        activation.push_back(s);
    }
    obj.push_back(Pair("activationstatus", activation));

    // The field that is not restored from the per-block record, and so the one
    // a divergence is most likely to show up in.
    //
    // Each pointer is also reported against the coins view, so one census
    // reading answers both questions: whether two nodes agree with each other
    // (the section hashes) and whether this node agrees with the one store
    // every node shares (anchored). A pointer that is not anchored is naming
    // money that is not where this node believes it is - the condition
    // CTIPAnchorHeight makes a block-level rule once it is set.
    UniValue ctip(UniValue::VARR);
    for (const std::pair<const uint8_t, SidechainCTIP>& p : scdb.GetCTIP()) {
        UniValue s(UniValue::VOBJ);
        s.push_back(Pair("nsidechain", (int)p.first));
        s.push_back(Pair("txid", p.second.out.hash.ToString()));
        s.push_back(Pair("n", (uint64_t)p.second.out.n));
        s.push_back(Pair("amount", ValueFromAmount(p.second.amount)));

        bool fAnchored = false;
        if (pcoinsTip) {
            const Coin& coin = pcoinsTip->AccessCoin(p.second.out);
            uint8_t nSidechainCoin;
            const bool fUnspent = !coin.IsSpent();
            s.push_back(Pair("viewunspent", fUnspent));
            if (fUnspent) {
                s.push_back(Pair("viewamount", ValueFromAmount(coin.out.nValue)));
                s.push_back(Pair("viewnsidechain",
                        coin.out.scriptPubKey.IsDrivechain(nSidechainCoin)
                            ? (int)nSidechainCoin : -1));
                fAnchored = coin.out.scriptPubKey.IsDrivechain(nSidechainCoin)
                        && nSidechainCoin == p.first
                        && coin.out.nValue == p.second.amount;
            }
        }
        s.push_back(Pair("anchored", fAnchored));
        ctip.push_back(s);
    }
    obj.push_back(Pair("ctip", ctip));

    UniValue failed(UniValue::VARR);
    for (const SidechainFailedWithdrawal& f : scdb.GetFailedWithdrawalCache()) {
        UniValue s(UniValue::VOBJ);
        s.push_back(Pair("nsidechain", (int)f.nSidechain));
        s.push_back(Pair("hash", f.hash.ToString()));
        failed.push_back(s);
    }
    obj.push_back(Pair("failedwithdrawals", failed));

    UniValue spent(UniValue::VARR);
    for (const SidechainSpentWithdrawal& sw : scdb.GetSpentWithdrawalCache()) {
        UniValue s(UniValue::VOBJ);
        s.push_back(Pair("nsidechain", (int)sw.nSidechain));
        s.push_back(Pair("hash", sw.hash.ToString()));
        s.push_back(Pair("blockhash", sw.hashBlock.ToString()));
        spent.push_back(s);
    }
    obj.push_back(Pair("spentwithdrawals", spent));

    // Appended after every pre-existing field so archived readings stay
    // comparable position-for-position as well as name-for-name.
    PushSCDBValidationFields(obj, pTip, hashGlobalConsensus, hashGlobalCommitment);

    return obj;
}

//! One unspent OP_DRIVECHAIN output found by the scan below.
struct DrivechainCoin
{
    COutPoint out;
    CAmount amount;
    int nHeight;
    bool fCoinBase;
};

//! Order the scan's findings so two nodes reporting the same UTXO snapshot
//! print the same bytes. The cursor walks the database in txid order, which is
//! neither stable across implementations nor useful to read; oldest first is
//! both, and it puts a forked lineage's root above the branch that left it.
static bool DrivechainCoinOrder(const DrivechainCoin& a, const DrivechainCoin& b)
{
    if (a.nHeight != b.nHeight)
        return a.nHeight < b.nHeight;
    if (a.out.hash != b.out.hash)
        return a.out.hash < b.out.hash;
    return a.out.n < b.out.n;
}

//! Collect every unspent OP_DRIVECHAIN output in the UTXO database, grouped by
//! the slot its script names.
//!
//! The cursor sees the database and not the in-memory coins cache, so the
//! caller must flush first or the answer describes a block already passed. The
//! snapshot's own block is returned rather than assumed to be the chain tip.
static bool ScanDrivechainCoins(CCoinsView* view, std::map<uint8_t, std::vector<DrivechainCoin>>& mapCoin, uint256& hashBestBlock)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    assert(pcursor);

    hashBestBlock = pcursor->GetBestBlock();

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        COutPoint key;
        Coin coin;
        if (!pcursor->GetKey(key) || !pcursor->GetValue(coin))
            return error("%s: unable to read value", __func__);

        uint8_t nSidechain;
        if (!coin.IsSpent() && coin.out.scriptPubKey.IsDrivechain(nSidechain)) {
            DrivechainCoin c;
            c.out = key;
            c.amount = coin.out.nValue;
            c.nHeight = coin.nHeight;
            c.fCoinBase = coin.fCoinBase;
            mapCoin[nSidechain].push_back(c);
        }

        pcursor->Next();
    }

    for (std::pair<const uint8_t, std::vector<DrivechainCoin>>& p : mapCoin)
        std::sort(p.second.begin(), p.second.end(), DrivechainCoinOrder);

    return true;
}

UniValue listdrivechaincoins(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "listdrivechaincoins ( nsidechain )\n"
            "\nEvery unspent sidechain treasury output, grouped by slot.\n"
            "\nThe treasury pointer a node reports names one output per slot. It\n"
            "cannot say whether the slot holds anything else, because no other\n"
            "call enumerates the treasury script - so value that came adrift from\n"
            "the pointer is not merely unspendable, it is invisible. This scans\n"
            "the unspent output set for the script itself and reports what is\n"
            "actually there, whatever the pointer says.\n"
            "\nTwo readings matter. A slot whose stranded amount is non-zero holds\n"
            "coins no withdrawal bundle can reach: its deposit chain forked, and\n"
            "the pointer followed one branch. A slot reporting ctipunspent false\n"
            "is worse - the pointer names an output that is gone, which is the\n"
            "state a treasury-anchored consensus rule could not accept.\n"
            "\nThis reads the unspent output set and changes nothing. It walks the\n"
            "whole set, so it takes as long as gettxoutsetinfo does.\n"
            "\nThe scan and the pointers are read at different instants. Compare\n"
            "bestblock against scdbblockhash before treating a mismatch as real;\n"
            "insync false means a block landed mid-call and the reading should be\n"
            "taken again.\n"
            "\nArguments:\n"
            "1. \"nsidechain\"   (numeric, optional) Report this slot only\n"
            "\nResult:\n"
            "{\n"
            "  \"height\"        : (numeric) height of the scanned snapshot\n"
            "  \"bestblock\"     : (string) block the scanned snapshot describes\n"
            "  \"scdbblockhash\" : (string) block the treasury pointers describe\n"
            "  \"insync\"        : (boolean) whether the two above agree\n"
            "  \"count\"         : (numeric) unspent treasury outputs found\n"
            "  \"amount\"        : (numeric) their total value\n"
            "  \"stranded\"      : (numeric) total value no pointer names\n"
            "  \"slots\" : [\n"
            "    {\n"
            "      \"nsidechain\"  : (numeric) the slot\n"
            "      \"active\"      : (boolean) whether the slot is occupied\n"
            "      \"count\"       : (numeric) unspent treasury outputs in it\n"
            "      \"amount\"      : (numeric) their total value\n"
            "      \"stranded\"    : (numeric) value the pointer does not name\n"
            "      \"hasctip\"     : (boolean) whether a pointer is recorded\n"
            "      \"ctipunspent\" : (boolean) whether that pointer's output exists\n"
            "      \"ctip\"        : { \"txid\", \"n\", \"amount\" } the pointer\n"
            "      \"coins\" : [\n"
            "        {\n"
            "          \"txid\", \"n\", \"amount\", \"height\", \"coinbase\",\n"
            "          \"isctip\" : (boolean) whether the pointer names this one\n"
            "        }, ...\n"
            "      ]\n"
            "    }, ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listdrivechaincoins", "")
            + HelpExampleCli("listdrivechaincoins", "2")
            + HelpExampleRpc("listdrivechaincoins", "2")
            );

    // Range-check before the truncation to uint8_t, as listsidechainctip does:
    // an out-of-range slot number would otherwise alias a real one.
    bool fFilter = !request.params.empty() && !request.params[0].isNull();
    int nFilter = 0;
    if (fFilter) {
        nFilter = request.params[0].get_int();
        if (nFilter < 0 || nFilter >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
            throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");
    }

    // The cursor reads the database, not the coins cache above it, so an
    // unflushed node would report the treasury as it stood at the last flush.
    FlushStateToDisk();

    std::map<uint8_t, std::vector<DrivechainCoin>> mapCoin;
    uint256 hashBestBlock;
    if (!ScanDrivechainCoins(pcoinsdbview.get(), mapCoin, hashBestBlock))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");

    // cs_main is deliberately not held across the scan - it walks the whole
    // unspent set and would stall block processing for as long as that takes.
    // The pointers are therefore read afterwards and may describe a later
    // block; the two block hashes are reported so the caller can see it.
    LOCK(cs_main);

    std::map<uint8_t, SidechainCTIP> mapCTIP = scdb.GetCTIP();
    const uint256 hashSCDBBlock = scdb.GetHashBlockLastSeen();

    int nHeight = 0;
    BlockMap::const_iterator it = mapBlockIndex.find(hashBestBlock);
    if (it != mapBlockIndex.end() && it->second)
        nHeight = it->second->nHeight;

    // Report a slot if the scan found coins in it or a pointer names it. A slot
    // with a pointer and no coins is the failure the ctipunspent field exists
    // for, so it must not be dropped for having nothing to list.
    std::set<uint8_t> setSlot;
    for (const std::pair<const uint8_t, std::vector<DrivechainCoin>>& p : mapCoin)
        setSlot.insert(p.first);
    for (const std::pair<const uint8_t, SidechainCTIP>& p : mapCTIP)
        setSlot.insert(p.first);

    CAmount amountTotal = 0;
    CAmount amountStrandedTotal = 0;
    int64_t nCountTotal = 0;

    UniValue slots(UniValue::VARR);
    for (const uint8_t nSidechain : setSlot) {
        if (fFilter && nSidechain != nFilter)
            continue;

        const std::vector<DrivechainCoin>& vCoin = mapCoin[nSidechain];

        std::map<uint8_t, SidechainCTIP>::const_iterator itCTIP = mapCTIP.find(nSidechain);
        const bool fHasCTIP = itCTIP != mapCTIP.end();

        CAmount amountSlot = 0;
        CAmount amountStranded = 0;
        bool fCTIPUnspent = false;

        UniValue coins(UniValue::VARR);
        for (const DrivechainCoin& coin : vCoin) {
            const bool fIsCTIP = fHasCTIP && itCTIP->second.out == coin.out;
            if (fIsCTIP)
                fCTIPUnspent = true;
            else
                amountStranded += coin.amount;
            amountSlot += coin.amount;

            UniValue c(UniValue::VOBJ);
            c.push_back(Pair("txid", coin.out.hash.ToString()));
            c.push_back(Pair("n", (int64_t)coin.out.n));
            c.push_back(Pair("amount", ValueFromAmount(coin.amount)));
            c.push_back(Pair("height", coin.nHeight));
            c.push_back(Pair("coinbase", coin.fCoinBase));
            c.push_back(Pair("isctip", fIsCTIP));
            coins.push_back(c);
        }

        UniValue s(UniValue::VOBJ);
        s.push_back(Pair("nsidechain", (int)nSidechain));
        s.push_back(Pair("active", scdb.IsSidechainActive(nSidechain)));
        s.push_back(Pair("count", (int64_t)vCoin.size()));
        s.push_back(Pair("amount", ValueFromAmount(amountSlot)));
        s.push_back(Pair("stranded", ValueFromAmount(amountStranded)));
        s.push_back(Pair("hasctip", fHasCTIP));
        s.push_back(Pair("ctipunspent", fCTIPUnspent));
        if (fHasCTIP) {
            UniValue ctip(UniValue::VOBJ);
            ctip.push_back(Pair("txid", itCTIP->second.out.hash.ToString()));
            ctip.push_back(Pair("n", (int64_t)itCTIP->second.out.n));
            ctip.push_back(Pair("amount", ValueFromAmount(itCTIP->second.amount)));
            s.push_back(Pair("ctip", ctip));
        }
        s.push_back(Pair("coins", coins));
        slots.push_back(s);

        amountTotal += amountSlot;
        amountStrandedTotal += amountStranded;
        nCountTotal += vCoin.size();
    }

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("height", nHeight));
    obj.push_back(Pair("bestblock", hashBestBlock.ToString()));
    obj.push_back(Pair("scdbblockhash", hashSCDBBlock.ToString()));
    obj.push_back(Pair("insync", hashBestBlock == hashSCDBBlock));
    obj.push_back(Pair("count", nCountTotal));
    obj.push_back(Pair("amount", ValueFromAmount(amountTotal)));
    obj.push_back(Pair("stranded", ValueFromAmount(amountStrandedTotal)));
    obj.push_back(Pair("slots", slots));

    return obj;
}

UniValue rebuildscdb(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "rebuildscdb\n"
            "\nRebuild the sidechain deposit cache by re-scanning local blocks.\n"
            "\nThe repair for a node whose sidechain state does not match its own\n"
            "chain - a stale or missing deposit cache, or a treasury tip that a\n"
            "reindex would disagree with. Until this existed the only remedy was a\n"
            "full reindex, which re-verifies every block in the chain.\n"
            "\nThis reads blocks only. It does not re-download anything, does not\n"
            "verify scripts, and does not touch the UTXO set, so it costs one pass\n"
            "over the blocks that could carry a deposit rather than a full\n"
            "revalidation. Blocks from before any sidechain was active are skipped\n"
            "without being read.\n"
            "\nIt needs this node's per-block sidechain records. A data directory\n"
            "missing them still needs a reindex, and the call reports that rather\n"
            "than rebuilding a partial cache.\n"
            "\nThe node is unavailable while this runs, and nothing is changed\n"
            "unless it completes: the rebuild is assembled separately and installed\n"
            "only on success.\n"
            "\nCompare getscdbhash before and after, or against another node at the\n"
            "same block, to see whether anything actually moved.\n"
            "\nResult:\n"
            "{\n"
            "  \"blockhash\"     : (string) block the rebuilt state describes\n"
            "  \"blocks\"        : (number) height of that block\n"
            "  \"consensushash\" : (string) consensus state after the rebuild\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("rebuildscdb", "")
            + HelpExampleRpc("rebuildscdb", "")
            );

    LOCK(cs_main);

    // RebuildSidechainDeposits verifies the rebuilt cache supports the treasury
    // BEFORE it installs it, and returns false without changing the live state
    // if it does not - so a false return here means the node was left exactly as
    // it was, and strError already names the slot and points at -reindex. A
    // legacy datadir with a mixed record history is the case that produces an
    // unsupported pointer; it must never be reported as a good rebuild, and now
    // it is reported as a failure that changed nothing rather than a broken
    // state installed live.
    std::string strError;
    if (!RebuildSidechainDeposits(strError))
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                "Sidechain rebuild failed: " + strError);

    const CBlockIndex* pTip = chainActive.Tip();

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("blockhash", scdb.GetHashBlockLastSeen().ToString()));
    obj.push_back(Pair("blocks", pTip ? pTip->nHeight : 0));
    obj.push_back(Pair("consensushash", scdb.GetConsensusHash(chainActive.Height()).ToString()));

    return obj;
}

UniValue getsidechaindbinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "getsidechaindbinfo\n"
            "Report which block the sidechain database is at, and whether that is\n"
            "the block the chain is on.\n"
            "\nThe two can only differ while a block is being connected. A node that\n"
            "reports them differing at rest is serving sidechain state, including\n"
            "the treasury tip of every slot, that does not correspond to its own\n"
            "chain - which makes it reject withdrawal payouts the rest of the\n"
            "network accepts. Until this call existed there was no way to observe\n"
            "that from outside the process.\n"
            "\nResult:\n"
            "{\n"
            "  \"hashblocklastseen\" : (string) block the sidechain database is at\n"
            "  \"chaintip\"          : (string) block the chain is on\n"
            "  \"insync\"            : (bool)   whether the two agree\n"
            "  \"blocks\"            : (number) height of the chain tip\n"
            "}\n"
            "\nExample:\n"
            + HelpExampleCli("getsidechaindbinfo", "")
            + HelpExampleRpc("getsidechaindbinfo", "")
            );

    LOCK(cs_main);

    const uint256 hashLastSeen = scdb.GetHashBlockLastSeen();
    const CBlockIndex* pTip = chainActive.Tip();
    const uint256 hashTip = pTip ? pTip->GetBlockHash() : uint256();

    // The sidechain database does not record a block until it has connected one
    // past genesis, so on a node still at the genesis tip its last-seen block is
    // null while the two are legitimately in step. Treat that as in sync, so the
    // report matches the help text rather than flagging a healthy fresh node.
    const bool fAtGenesis = pTip && pTip->GetBlockHash() == Params().GetConsensus().hashGenesisBlock;
    const bool fInSync = hashLastSeen == hashTip || (hashLastSeen.IsNull() && (!pTip || fAtGenesis));

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hashblocklastseen", hashLastSeen.ToString()));
    ret.push_back(Pair("chaintip", hashTip.ToString()));
    ret.push_back(Pair("insync", fInSync));
    ret.push_back(Pair("blocks", pTip ? pTip->nHeight : 0));

    return ret;
}

UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "echo|echojson \"message\" ...\n"
            "\nSimply echo back the input arguments. This command is for testing.\n"
            "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in"
            "skydoge-cli and the GUI. There is no server-side difference."
        );

    return request.params;
}

static UniValue getinfo_deprecated(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_METHOD_NOT_FOUND,
        "getinfo\n"
        "\nThis call was removed in version 0.16.0. Use the appropriate fields from:\n"
        "- getblockchaininfo: blocks, difficulty, chain\n"
        "- getnetworkinfo: version, protocolversion, timeoffset, connections, proxy, relayfee, warnings\n"
        "- getwalletinfo: balance, keypoololdest, keypoolsize, paytxfee, unlocked_until, walletversion\n"
        "\nskydoge-cli has the option -getinfo to collect and format these in the old format."
    );
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getmemoryinfo",          &getmemoryinfo,          {"mode"} },
    { "control",            "logging",                &logging,                {"include", "exclude"}},
    { "util",               "validateaddress",        &validateaddress,        {"address"} }, /* uses wallet if enabled */
    { "util",               "createmultisig",         &createmultisig,         {"nrequired","keys"} },
    { "util",               "verifymessage",          &verifymessage,          {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, {"privkey","message"} },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            {"timestamp"}},
    { "hidden",             "echo",                   &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "getinfo",                &getinfo_deprecated,     {}},

    /* Drivechain rpc commands for the user and sidechains */
    { "Drivechain",  "addwithdrawal",                 &addwithdrawal,                   {"nsidechain", "hash"}},
    { "Drivechain",  "createcriticaldatatx",          &createcriticaldatatx,            {"amount", "height", "criticalhash"}},
    { "Drivechain",  "listsidechainctip",             &listsidechainctip,               {"nsidechain"}},
    { "Drivechain",  "listsidechaindeposits",         &listsidechaindeposits,           {"nsidechain"}},
    { "Drivechain",  "countsidechaindeposits",        &countsidechaindeposits,          {"nsidechain"}},
    { "Drivechain",  "receivewithdrawalbundle",       &receivewithdrawalbundle,         {"nsidechain","rawtx"}},
    { "Drivechain",  "verifybmm",                     &verifybmm,                       {"blockhash", "bmmhash", "nsidechain"}},
    { "Drivechain",  "verifydeposit",                 &verifydeposit,                   {"blockhash", "txid", "ntx"}},
    { "Drivechain",  "listpreviousblockhashes",       &listpreviousblockhashes,         {}},
    { "Drivechain",  "listactivesidechains",          &listactivesidechains,            {}},
    { "Drivechain",  "listsidechainactivationstatus", &listsidechainactivationstatus,   {}},
    { "Drivechain",  "listsidechainproposals",        &listsidechainproposals,          {}},
    { "Drivechain",  "acksidechain",                  &acksidechain,   {"hash"}},
    { "Drivechain",  "nacksidechain",                 &nacksidechain,          {"hash"}},
    { "Drivechain",  "listhashsidechain",                 &listhashsidechain,          {}},
    { "Drivechain",  "getsidechainactivationstatus",  &getsidechainactivationstatus,    {}},
    { "Drivechain",  "listsidechainproposalacks",     &listsidechainproposalacks,       {}},

    { "Drivechain",  "createsidechainproposal",       &createsidechainproposal,         {"nsidechain", "title", "description", "keyhash", "nversion", "hashid1", "hashid2"}},
    { "Drivechain",  "clearwithdrawalvotes",          &clearwithdrawalvotes,            {}},
    { "Drivechain",  "setwithdrawalvote",             &setwithdrawalvote,               {"vote", "nsidechain", "hashwithdrawal"}},
    { "Drivechain",  "listwithdrawalvotes",           &listwithdrawalvotes,             {}},
    { "Drivechain",  "getaveragefee",                 &getaveragefee,                   {"numblocks", "startheight"}},
    { "Drivechain",  "getworkscore",                  &getworkscore,                    {"nsidechain", "hashwithdrawal"}},
    { "Drivechain",  "havespentwithdrawal",           &havespentwithdrawal,             {"hashwithdrawal", "nsidechain"}},
    { "Drivechain",  "havefailedwithdrawal",          &havefailedwithdrawal,            {"hashwithdrawal", "nsidechain"}},
    { "Drivechain",  "listcachedwithdrawaltx",        &listcachedwithdrawaltx,          {"nsidechain", "verbose"}},
    { "Drivechain",  "listwithdrawalstatus",          &listwithdrawalstatus,            {"nsidechain"}},
    { "Drivechain",  "listspentwithdrawals",          &listspentwithdrawals,            {}},
    { "Drivechain",  "listfailedwithdrawals",         &listfailedwithdrawals,           {}},
    { "Drivechain",  "gettotalscdbhash",              &gettotalscdbhash,                {}},
    { "Drivechain",  "getscdbdataforblock",           &getscdbdataforblock,             {"blockhash"}},
    { "Drivechain",  "listfailedbmm",                 &listfailedbmm,                   {}},
    { "Drivechain",  "getactivesidechaincount",       &getactivesidechaincount,         {}},
    { "Drivechain",  "getsidechaindbinfo",            &getsidechaindbinfo,              {}},
    { "Drivechain",  "getscdbhash",                   &getscdbhash,                     {}},
    { "Drivechain",  "getscdbstate",                  &getscdbstate,                    {}},
    { "Drivechain",  "rebuildscdb",                   &rebuildscdb,                     {}},
    { "Drivechain",  "listdrivechaincoins",           &listdrivechaincoins,             {"nsidechain"}},

    /* Coin News RPC */
    { "CoinNews",    "getopreturndata",               &getopreturndata,                 {"blockhash"}},
    { "CoinNews",    "listnews",                      &listnews,                        {"count","header"}},
    { "CoinNews",    "listnewstypes",                 &listnewstypes,                   {}},
    { "CoinNews",    "createnewstype",                &createnewstype,                  {"title","header","days"}},
    { "CoinNews",    "removenewstype",                &removenewstype,                  {"hash"}},

};

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
