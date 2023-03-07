// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addressbook.h>

AddressBook::AddressBook()
{
}

void AddressBook::AddMultisigPartner(const MultisigPartner& partner)
{
    vMultisigPartner.push_back(partner);
}

std::vector<MultisigPartner> AddressBook::GetMultisigPartners() const
{
    return vMultisigPartner;
}
