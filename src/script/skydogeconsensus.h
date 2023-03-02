// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The skydoge Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SKYDOGE_SKYDOGECONSENSUS_H
#define SKYDOGE_SKYDOGECONSENSUS_H

#include <stdint.h>

#if defined(BUILD_SKYDOGE_INTERNAL) && defined(HAVE_CONFIG_H)
#include <config/skydoge-config.h>
  #if defined(_WIN32)
    #if defined(DLL_EXPORT)
      #if defined(HAVE_FUNC_ATTRIBUTE_DLLEXPORT)
        #define EXPORT_SYMBOL __declspec(dllexport)
      #else
        #define EXPORT_SYMBOL
      #endif
    #endif
  #elif defined(HAVE_FUNC_ATTRIBUTE_VISIBILITY)
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #endif
#elif defined(MSC_VER) && !defined(STATIC_LIBSKYDOGECONSENSUS)
  #define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
  #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SKYDOGECONSENSUS_API_VER 1

typedef enum skydogeconsensus_error_t
{
    skydogeconsensus_ERR_OK = 0,
    skydogeconsensus_ERR_TX_INDEX,
    skydogeconsensus_ERR_TX_SIZE_MISMATCH,
    skydogeconsensus_ERR_TX_DESERIALIZE,
    skydogeconsensus_ERR_AMOUNT_REQUIRED,
    skydogeconsensus_ERR_INVALID_FLAGS,
} skydogeconsensus_error;

/** Script verification flags */
enum
{
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), // evaluate P2SH (BIP16) subscripts
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), // enforce strict DER (BIP66) compliance
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY           = (1U << 4), // enforce NULLDUMMY (BIP147)
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), // enable CHECKLOCKTIMEVERIFY (BIP65)
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10), // enable CHECKSEQUENCEVERIFY (BIP112)
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS             = (1U << 11), // enable WITNESS (BIP141)
    skydogeconsensus_SCRIPT_FLAGS_VERIFY_ALL                 = skydogeconsensus_SCRIPT_FLAGS_VERIFY_P2SH | skydogeconsensus_SCRIPT_FLAGS_VERIFY_DERSIG |
                                                               skydogeconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY | skydogeconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                                               skydogeconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY | skydogeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS
};

/// Returns 1 if the input nIn of the serialized transaction pointed to by
/// txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
/// the additional constraints specified by flags.
/// If not nullptr, err will contain an error/success code for the operation
EXPORT_SYMBOL int skydogeconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
                                                 const unsigned char *txTo        , unsigned int txToLen,
                                                 unsigned int nIn, unsigned int flags, skydogeconsensus_error* err);

EXPORT_SYMBOL int skydogeconsensus_verify_script_with_amount(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen, int64_t amount,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    unsigned int nIn, unsigned int flags, skydogeconsensus_error* err);

EXPORT_SYMBOL unsigned int skydogeconsensus_version();

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // SKYDOGE_SKYDOGECONSENSUS_H
