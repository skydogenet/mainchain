// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef APICLIENT_H
#define APICLIENT_H

#include <amount.h>
#include <uint256.h>

#include <string>
#include <vector>

#include <boost/property_tree/json_parser.hpp>

/** Whether the transaction-replay lookup may contact the outside world. */
static const bool DEFAULT_REPLAY_CHECK = false;

class APIClient
{
public:
    APIClient();

    /**
     * Ask whether txid also exists on the other chain.
     *
     * Sets fDetermined only when an answer was actually obtained. A false
     * return with fDetermined unset means the question could not be answered -
     * the lookup is switched off, or the request failed - and must not be
     * treated as "not replayed".
     */
    bool IsTxReplayed(const uint256& txid, bool& fDetermined);

private:
    /*
     * Send json request
     */
    bool SendRequest(const std::string& json, boost::property_tree::ptree &ptree);
};

#endif // APICLIENT_H
