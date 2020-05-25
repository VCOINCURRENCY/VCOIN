// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#include <mutex>
#include "metrics.h"
#include "crypto/equihash.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Vcoin' + blake2s(b'TODO').hexdigest()
 *
 * CBlock(hash=00052461, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=94c7ae, nTime=1516980000, nBits=1f07ffff, nNonce=6796, vtx=1)
 *   CTransaction(hash=94c7ae, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 94c7ae
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "VCoinc7a7746f7ab10a87a5e14516ccc7ff639626f21de9a2dd6f4306c630713e6e27";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "VCC";
	bip44CoinType = 19167;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
	consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 125000;

	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 125100;

	consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 250000;		// Approx January 12th

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 372500;  // Approx July 2nd - Zel Team Boulder Meetup 

	consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xe1;
        pchMessageStart[2] = 0xd0;
        pchMessageStart[3] = 0xf4;
        vAlertPubKey = ParseHex("04025b2cf3a116782a69bb68cb4ae5ba3b7f05069f7139b75573dd28e48f8992d95c118122b618d4943456ad64e7356b0b45b2ef179cbe3d9767a2426662d13d32"); //Zel Technologies GmbH
        nDefaultPort = 16325;
        nPruneAfterHeight = 100000;


        genesis = CreateGenesisBlock(
            1589003483,
            uint256S("0x00000000000000000000000000000000000000000000000000000000000004da"),
            ParseHex("003423076680590be15f12590c1ba9f51663aab1ea164aac71608c62e9642b941a8eeaa0d28f57dcacaf0ed9b893cf9b0bb52c9a87e078fd016316919980a71fd047d688695d17b9de92f51350c8b6c21ed6632206135885eaea05258c3ab2610e9434ecbd813ec3c026613f1a658e0f4fcff7033d2f1c86295f5c58095c112ee99243939331f4f532a8a7bf8db273273d85eb26649bbb6791402fe3dea546914fe51ada051833390446a043e3a6aa89c0d3310b4c240371fba1fc473c1e901aaaa4b66055b87312ea08a7eca90670a95e5a045fd43de39dd46fd0a916c44040681ded5ff5d53e0b6920ae2e8fe363839034691761c2730615397aa00e7d19bea9342dd3c6c3d968f07825bf1349794d0b0f14bf4dc58f6d711054a3727acb0ec68e4eb86917259ef312f38c8b52a193b332ed36df74e1a96ba17525a47ef6910d1768f953d2c8a5220a5e66149dc8b00107db4e6a81d566a2b472f7024564e546d1b3d1b2444b4a80e4e28dcd36b88576ff2ed0e77d8a3d9fed01dea7a3ef9a0b49c538650f0d5a47a3480e9beb45271a659e2dca649ad22725e8f745624ae67f98dc3213a3efbd5a1b4d73016e38897b663ac286071ed790368fad3e83288e11bedce40befe966bfb1db9fa9381431ec08bfdd1487ba43d27d8f4d08dcecb01051f11e452a86324aba41c497e1f0a06c0ba11eb41d824305146a885a107d5d53ea76ee6a690b4ac924b82a56445b3d73f8a425493ec0baab55e6001eeeba5f8a5c1b177c071f290db1c2cb96b41bf5dd4b30175c73e81f77933af19fd67ddddaf2ed3fb7ee4603c15c924e0e3f9e4c045455831506d213223d8caa7f2b3450782ad12f9ebff04ccbc519b53386528793567c3bca550f95862ea0653acbf312368215efe64ec6a19a807828f876a05a99392323fba58823e1c381bd71dfe9fc0354f94b33ce71a6c820e10c6436d0de70649e4ecb0e19b5edf46a42036a8f80f3f0290f6cab4c761a690b3618e8994c87d1dd3824cba3c67325e67c3107c234b7c4d6b35212bdbe4da542ea70ca2a101afd007a05b50ae13689af83450c806532f9fdbf5eae9cf8b02e1f8e52b88dad77c3eb232dd96c2ce758855fb2562a739e28260babd7463fe996fcda320ea32015b4d43facea6a0c9dd785ace164139ef97e82c2389657e404c011fa8fcac4c1a5b4c0b18edb42f73ddf9f61ac16c36c53e353a5fd6891a75e35c04e0e8c66bee0291fb5ad17763a7b79ec1e353d34ffdbfa63a1fe659523a15f163f4bf29fccae22b7611f93ad12adaa4fb70ca2dd076f43323f722f060422e57b8dde0cb0fb89330bfb7793e30a719bc3f4afede3de45e6b3780573172bb78d05a5605ba3e9723ba9f90d2730485d03061754ca639991c6f723cf11cdc33e5ec585b10cc2f2057177bed94fbb5b46f595649e571599b0a24f49572d6706c4d47c9d8feccaa49668ef889abc47dfb2dd05f22d23c4177d41c16b64d4f535ccc5495b5e1edd33e1b386125c50fbf476e8d035e22d1e84729dac811eef826f076462c58d8cf62f86681d620c2c17df7f2e91a5abf8fbf90ff9b854df1d3ffed70713da36af27590d8de34dddf7c43922db127d17a8fdb119573127ece9eff5db3559174933ad989e139ded4dd4f0d708992544d290a3d747f8024d6e759ac38bdd5e73ad29cade0a0c53c733c7a882ce774ddd525210b947972349d6a2130df3eedee5223a4167b608da449b45c3480cf27874dae7d1a8c955da31f2c176dc1dbed1180aef58d40f91d0ff95e8324556a5df2faa1d9e194e44fbdaf57bbc68fdf4bdf5bdd1c49479b31239b2cf0cd89d4562043462405fe175a05d32506b4ea981162e2843f0a3d37883f09ba38f3129f748e7637b3daf"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x00037abd0c64ea64e5bc32f5f49f26972807ca29732b355c9a733dbb41d7531b"));
        assert(genesis.hashMerkleRoot == uint256S("0x6167f4132766090f0ca43bab4883a0a47323c682bff06b5d1dbcd9f2b7a3c527"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("vps.zel.network", "singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsone.zel.network", "bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpstwo.zel.network", "frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsthree.zel.network", "newyork.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vps.vcoin.online", "dnsseed.vcoin.online")); // TheTrunk

        // guarantees the first 2 characters, when base58 encoded, are "V1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x0F,0xC5};
        // guarantees the first 2 characters, when base58 encoded, are "V3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x0F,0xC9};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "za";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewa";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivka";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        strSporkKey = "04f5382d5868ae49aedfd67efce7c0f56a66a9405a2cc13f8ef236aabb3f0f1d00031f9b9ca67edc93044918a1cf265655108bab531e94c7d48918e40a94a34f77";
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Not being used, but could be in the future
        networkID = CBaseChainParams::Network::MAIN;
        strZelnodeTestingDummyAddress= "t1Ub8iNuaoCAKTaiVyCh8d3iZ31QJFxnGzU";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock), //Halep won French Open 2018
            1589003483,     // * UNIX timestamp of last checkpoint block
            0,              // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1               // * estimated number of transactions per day
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        // nSproutValuePoolCheckpointHeight = 520633;
        // nSproutValuePoolCheckpointBalance = 22145062442933;
        // fZIP209Enabled = true;
        // hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");
    }
};
static CMainParams mainParams;

/**
 * testnet-kamiooka
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TESTVCC";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
        Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
        Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 70;

	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 100;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 120;

	    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 720;


        consensus.nZawyLWMAAveragingWindow = 60;
	    consensus.eh_epoch_fade_length = 10;

	    //eh_epoch_1 = eh96_5;
    eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;


        pchMessageStart[0] = 0x69;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0x28;
        pchMessageStart[3] = 0xdc;
        vAlertPubKey = ParseHex("044b5cb8fd1db34e2d89a93e7becf3fb35dd08a81bb3080484365e567136403fd4a6682a43d8819522ae35394704afa83de1ef069a3104763fd0ebdbdd505a1386"); //Zel Technologies GmbH

        nDefaultPort = 26325;

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1589007081,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000082"),
            ParseHex("00002e0bb646fda47e19a2bb002d780b6decdee5c60b3322c939115afe9e0391f6cc4aa7b25bf639043709f2d2ade28b93209adff747fdbdb90f14e53d2b5b28db33a4c7d6b55361ab340f9c3094c214e512a5500b4cd52bc888e00f87c9d2e19649d6f672eb9dcd0f2c187575e65ae2c9dec143a223a6ec9535accfdf66137ff6e31f146641376554d3f56424d13aecff3c1b48e3326799215b5de2d25536fd2b1e25ab4bb3cc4703a6116371a91085ff264280c85ae2c247185e3cef15a66bcdf8543db5fccaa4b8e52dfae9952bed633905b9ab8083d0364f0780851eeffc691ed9cdda8e0236cac362c4910e67b58465138ff9a66997fb2e9b32085005cca4d89f24db02a163b146586cc88a3dbc420ab992f129e8d94ff15490cf41b96d3ddfae19e0471c045eaede994b6949cca1c7c1b6fa25ae1bd43ef232ffaf31110f43c950a734fc44d7dec230da7762e6005e5a07099a5d7983a9e5064131321d8853ad9152010e7afe4e3032a9fc29731d536d0496a00195cf99053c3f1e1f4229a8ee6013665a7bf8c266343c30e007d7cf2a7b2580fd5751d60f3cb2f2120146da75c4023a464cebeea097d8c4f9eface6ddf6b7459f6839274c4ab96d682283fea9c2a9ab705c9512948f73311e950e9a805afc51849dc89da14ec6ee58af19b39928251f55868fe8d77c9704985fdc490a6f9ab4c54d037fad68b0d139788f73d1ebb752e6c8d6ce50c25a33237b18f1368b27cff0d39678ebbe5562acdb063c0d0c1f98b31f7ac176f92565f1ca0a19d49c370b67163914a34795b8190e19275ca5dad331d9051004d605b40ddabd58b94b9561131996421e29781a37a12d23454250292c4bd565a0328d9e9d1c6dcf27bd279d07e56e81220547ddabff45c28079a772147371a8180a9027441243610357ce9608683c54f5bf6d76902700f4437997467b931994b33e19cf45410bb30faf9a1dbf696a9cf80029ef398676ae363b6de661ff6f8f063fd0954152cfcce42910fe811fb27d5e913fef543d746a005a6ebd5def41f86edef38eba363cfde46607fe7c4d3326aa296f2fc1eef040a41e4f319d93541a527231c7c722f33e8da32f356a4fba26815c00522f6c91f2ccaf592f8b1b3640aa7e015641c117db1c6068abb73de1d09983360710155153c71f5ff906e4039076169a509023e21790882d8ddd24c3073ffe240bee0ef11c4a0b9184ada57accb64dad5f3e99838513c179ebba59c5419dab21d8c369b625c40e517484275147fc5fda7037df3662dedfd9daa10bac1460140462e7a6259ba76d9e41bc9f28fa02774abf5f9f4e0f0521cd219e8fa1aa59964061fa035dfaf1f726230acbb06c5253bfe725e103c71acf4d29d6575060851c0e546e269d77ddb904974ccffd9b0f65e6be9a9201892321608f918b1990a13bbca877e9355a4baf56056e08a7669f1f951d9bd08e78f1501190021dfbc30869275cce075b283ff2358b80c5da56d478fbbbab12ef0dc163a659a14e40e510a2ce7045a6152d7a5a0454ededfa9333373980538eab34f259b7d91fb73507ef068704454b87b3f7115591bb3b4b03e65d226f06d3baa533c5f151fb27457f29c0cf59d54ab8f32d647afcaa5d19f709b1e07c54cc666227bea7be5cd902a2fdd0bc2b07876e0380e7899b5624780faaec3b06c4a48a58827bf9bed740da0a97435c3d90b7e0370403f449959f66a385a240fe6aecaee8b863366bcf3a68e3207ea6df5b4e22b5686e54b0a16613ef424103138c0d034540c2437ed5f65d593a8dbdbd9b72fa1c0c57156bec6f45965174734ef5b28e5ea8ba0a701928fc7918478393689e62f4f321b39aa04479636219fcc0ea11c9e1274efcb1f773ac0325cf455efa83"),
            0x2007ffff, 4, 0);
        
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x07ea7854890e27bcd8866b1a400231a46cdba4717c4ae3d7ff4795b44578b033"));
        assert(genesis.hashMerkleRoot == uint256S("0x6167f4132766090f0ca43bab4883a0a47323c682bff06b5d1dbcd9f2b7a3c527"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("test.vps.zel.network", "test.singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsone.zel.network", "test.bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpstwo.zel.network", "test.frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsthree.zel.network", "test.newyork.zel.network")); // MilesManley
        //vSeeds.push_back(CDNSSeedData("vps.testnet.vcoin.online", "dnsseedtestnet.vcoin.online")); // TheTrunk


        // guarantees the first 2 characters, when base58 encoded, are "v1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0xD8};
        // guarantees the first 2 characters, when base58 encoded, are "v2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1D,0xDA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestacadia";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestacadia";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestacadia";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        strSporkKey = "0408c6a3a6cacb673fc38f27c75d79c865e1550441ea8b5295abf21116972379a1b49416da07b7d9b40fb9daf8124f309c608dfc79756a5d3c2a957435642f7f1a";
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Currently not being used.
        networkID = CBaseChainParams::Network::TESTNET;
        strZelnodeTestingDummyAddress= "tmXxZqbmvrxeSFQsXmm4N9CKyME767r47fS";




        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1589007081,  // * UNIX timestamp of last checkpoint block
            0,           // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            1            // * estimated number of transactions per day after checkpoint 720 newly mined +30 for txs that users are doing
                         //   total number of tx / (checkpoint block height / (24 * 24))
        };

    // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        //nSproutValuePoolCheckpointHeight = 440329;
        //nSproutValuePoolCheckpointBalance = 40000029096803;
        //fZIP209Enabled = true;
        //hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nDigishieldMaxAdjustUp = 0; // Turn off adjustment up

        consensus.nPowTargetSpacing = 2 * 60;
	consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight =
	    Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

    consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170006;
    consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

	consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;

        pchMessageStart[0] = 0xab;
        pchMessageStart[1] = 0xe3;
        pchMessageStart[2] = 0x2f;
        pchMessageStart[3] = 0x4f;
        nDefaultPort = 26326;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(
            1589008163,
            uint256S("0000000000000000000000000000000000000000000000000000000000000003"),
            ParseHex("09585c9c61df8c7c72181da2748385cdd13a0dbe20fa388d6f01903fdd503dd5eb959bbf"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x0514aa839ae6fef49f3ac58b96b323d8e02faaa044c80c26324c7d0cad7b230a"));
        assert(genesis.hashMerkleRoot == uint256S("0x6167f4132766090f0ca43bab4883a0a47323c682bff06b5d1dbcd9f2b7a3c527"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        networkID = CBaseChainParams::Network::REGTEST;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("6167f4132766090f0ca43bab4883a0a47323c682bff06b5d1dbcd9f2b7a3c527")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0xD8};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1D,0xDA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}


// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}
std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list

    int current_height = (int)blockheight;
    if (current_height < 0)
        current_height = 0;

    // When checking to see if the activation height is above the fade length, we subtract the fade length from the
    // current height and run it through the NetworkUpgradeActive method
    int modified_height = (int)(current_height - params.GetConsensus().eh_epoch_fade_length);
    if (modified_height < 0)
        modified_height = 0;

    // check to see if the block height is greater then the overlap period ( height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        return 1;
    }

    // check to see if the block height is in the overlap period.
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        ehparams[1]=params.eh_epoch_2_params();
        return 2;
    }

    // check to see if the block height is greater then the overlap period (height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }

    // check to see if the block height is in the overlap period
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        ehparams[1]=params.eh_epoch_1_params();
        return 2;
    }

    // return the block height is less than the upgrade height params
    ehparams[0]=params.eh_epoch_1_params();
    return 1;
}
