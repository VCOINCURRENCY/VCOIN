// Copyright (c) 2019 The Zel developers
// Copyright (c) 2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VCCCASH_UTIL_TEST_H
#define VCCCASH_UTIL_TEST_H

#include "key_io.h"
#include "wallet/wallet.h"
#include "vcoin/JoinSplit.hpp"
#include "vcoin/Note.hpp"
#include "vcoin/NoteEncryption.hpp"
#include "vcoin/zip32.h"

// Sprout
CWalletTx GetValidSproutReceive(ZCJoinSplit& params,
                                const libvcoin::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                int32_t version = 2);
CWalletTx GetInvalidCommitmentSproutReceive(ZCJoinSplit& params,
                                const libvcoin::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                int32_t version = 2);
libvcoin::SproutNote GetSproutNote(ZCJoinSplit& params,
                                   const libvcoin::SproutSpendingKey& sk,
                                   const CTransaction& tx, size_t js, size_t n);
CWalletTx GetValidSproutSpend(ZCJoinSplit& params,
                              const libvcoin::SproutSpendingKey& sk,
                              const libvcoin::SproutNote& note,
                              CAmount value);

// Sapling
static const std::string T_SECRET_REGTEST = "cND2ZvtabDbJ1gucx9GWH6XT9kgTAqfb6cotPt5Q5CyxVDhid2EN";

struct TestSaplingNote {
    libvcoin::SaplingNote note;
    SaplingMerkleTree tree;
};

const Consensus::Params& RegtestActivateAcadia();

void RegtestDeactivateAcadia();

libvcoin::SaplingExtendedSpendingKey GetTestMasterSaplingSpendingKey();

CKey AddTestCKeyToKeyStore(CBasicKeyStore& keyStore);

/**
 * Generate a dummy SaplingNote and a SaplingMerkleTree with that note's commitment.
 */
TestSaplingNote GetTestSaplingNote(const libvcoin::SaplingPaymentAddress& pa, CAmount value);

CWalletTx GetValidSaplingReceive(const Consensus::Params& consensusParams,
                                 CBasicKeyStore& keyStore,
                                 const libvcoin::SaplingExtendedSpendingKey &sk,
                                 CAmount value);

#endif // VCCCASH_UTIL_TEST_H
