// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRESSBOOK_H
#define BITCOIN_ADDRESSBOOK_H

#include <string>
#include <vector>

#include <serialize.h>

struct MultisigPartner {
    std::string strName;
    std::string strPubKey;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(strName);
        READWRITE(strPubKey);
    }
};

class AddressBook
{
public:
    AddressBook();

    /** Add Multisig partner to cache */
    void AddMultisigPartner(const MultisigPartner& partner);

    /** Get a list of multisig partners */
    std::vector<MultisigPartner> GetMultisigPartners() const;

private:
    /** Cache of multisig partners */
    std::vector<MultisigPartner> vMultisigPartner;

};

#endif // BITCOIN_ADDRESSBOOK_H
