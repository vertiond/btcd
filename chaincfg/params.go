// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/chaincfg/difficulty"
	"github.com/btcsuite/btcd/wire"

    "github.com/bitgoin/lyra2rev2"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// regressionPowLimit is the highest proof of work value a Bitcoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// testNet3PowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// simNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// sigNetPowLimit is the highest proof of work value a bitcoin block can
	// have for the signet test network. It is the value 0x0377ae << 216.
	sigNetPowLimit = new(big.Int).Lsh(new(big.Int).SetInt64(0x0377ae), 216)

	// DefaultSignetChallenge is the byte representation of the signet
	// challenge for the default (public, Taproot enabled) signet network.
	// This is the binary equivalent of the bitcoin script
	//  1 03ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430
	//  0359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c4 2
	//  OP_CHECKMULTISIG
	DefaultSignetChallenge, _ = hex.DecodeString(
		"512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d" +
			"1e086be430210359ef5021964fe22d6f8e05b2463c9540ce9688" +
			"3fe3b278760f048f5189f2e6c452ae",
	)

	// DefaultSignetDNSSeeds is the list of seed nodes for the default
	// (public, Taproot enabled) signet network.
	DefaultSignetDNSSeeds = []DNSSeed{
		{"178.128.221.177", false},
		{"2a01:7c8:d005:390::5", false},
		{"v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333", false},
	}
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// DNSSeed identifies a DNS seed.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// ConsensusDeployment defines details related to a specific consensus rule
// change that is voted in.  This is part of BIP0009.
type ConsensusDeployment struct {
	// BitNumber defines the specific bit number within the block version
	// this particular soft-fork deployment refers to.
	BitNumber uint8

	// StartTime is the median block time after which voting on the
	// deployment starts.
	StartTime uint64

	// ExpireTime is the median block time after which the attempted
	// deployment expires.
	ExpireTime uint64
}

// Constants that define the deployment offset in the deployments field of the
// parameters for each deployment.  This is useful to be able to get the details
// of a specific deployment by name.
const (
	// DeploymentTestDummy defines the rule change deployment ID for testing
	// purposes.
	DeploymentTestDummy = iota

	// DeploymentCSV defines the rule change deployment ID for the CSV
	// soft-fork package. The CSV package includes the deployment of BIPS
	// 68, 112, and 113.
	DeploymentCSV

	// DeploymentSegwit defines the rule change deployment ID for the
	// Segregated Witness (segwit) soft-fork package. The segwit package
	// includes the deployment of BIPS 141, 142, 144, 145, 147 and 173.
	DeploymentSegwit

	// DeploymentTaproot defines the rule change deployment ID for the
	// Taproot (+Schnorr) soft-fork package. The taproot package includes
	// the deployment of BIPS 340, 341 and 342.
	DeploymentTaproot

	// NOTE: DefinedDeployments must always come last since it is used to
	// determine how many defined deployments there currently are.

	// DefinedDeployments is the number of currently defined deployments.
	DefinedDeployments
)

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// The function used to calculate the proof of work value for a block
	PoWFunction func(b []byte) chainhash.Hash

    // The function used to calculate the difficulty of a given block
    DiffCalcFunction func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error)

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// These fields define the block heights at which the specified softfork
	// BIP became active.
	BIP0034Height int32
	BIP0065Height int32
	BIP0066Height int32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	SubsidyReductionInterval int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// These fields are related to voting on consensus rule changes as
	// defined by BIP0009.
	//
	// RuleChangeActivationThreshold is the number of blocks in a threshold
	// state retarget window for which a positive vote for a rule change
	// must be cast in order to lock in a rule change. It should typically
	// be 95% for the main network and 75% for test networks.
	//
	// MinerConfirmationWindow is the number of blocks in each threshold
	// state retarget window.
	//
	// Deployments define the specific consensus rule changes to be voted
	// on.
	RuleChangeActivationThreshold uint32
	MinerConfirmationWindow       uint32
	Deployments                   [DefinedDeployments]ConsensusDeployment

	// Mempool parameters
	RelayNonStdTxs bool

	// Human-readable part for Bech32 encoded segwit addresses, as defined
	// in BIP 173.
	Bech32HRPSegwit string

	// Address encoding magics
	PubKeyHashAddrID        byte // First byte of a P2PKH address
	ScriptHashAddrID        byte // First byte of a P2SH address
	PrivateKeyID            byte // First byte of a WIF private key
	WitnessPubKeyHashAddrID byte // First byte of a P2WPKH address
	WitnessScriptHashAddrID byte // First byte of a P2WSH address

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32
}

/* calcDiff returns a bool given two block headers.  This bool is
true if the correct dificulty adjustment is seen in the "next" header.
Only feed it headers n-2016 and n-1, otherwise it will calculate a difficulty
when no adjustment should take place, and return false.
Note that the epoch is actually 2015 blocks long, which is confusing. */
func calcDiffAdjustBitcoin(start, end wire.BlockHeader, p *Params) uint32 {
	minRetargetTimespan := int64(p.TargetTimespan.Seconds()) / p.RetargetAdjustmentFactor
	maxRetargetTimespan := int64(p.TargetTimespan.Seconds()) * p.RetargetAdjustmentFactor
	duration := end.Timestamp.UnixNano() - start.Timestamp.UnixNano()
	if duration < minRetargetTimespan {
		duration = minRetargetTimespan
	} else if duration > maxRetargetTimespan {
		duration = maxRetargetTimespan
	}

	// calculation of new 32-byte difficulty target
	// first turn the previous target into a big int
	prevTarget := difficulty.CompactToBig(start.Bits)
	// new target is old * duration...
	newTarget := new(big.Int).Mul(prevTarget, big.NewInt(duration))
	// divided by 2 weeks
	newTarget.Div(newTarget, big.NewInt(int64(p.TargetTimespan / time.Second)))

  powLimit := difficulty.CompactToBig(p.PowLimitBits)

	// clip again if above minimum target (too easy)
	if newTarget.Cmp(powLimit) > 0 {
		newTarget.Set(powLimit)
	}

	// calculate and return 4-byte 'bits' difficulty from 32-byte target
	return difficulty.BigToCompact(newTarget)
}

func BTCDiff (r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  epochLength := int32(p.TargetTimespan / p.TargetTimePerBlock)
  var err error
  var cur, prev, epochStart wire.BlockHeader

  offsetHeight := height - startheight

  // seek to n-1 header
  _, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  // read in n-1
  err = prev.Deserialize(r)
  if err != nil {
    return 0, err
  }

    // seek to curHeight header and read in
  _, err = r.Seek(int64(80*(offsetHeight)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = cur.Deserialize(r)
  if err != nil {
    return 0, err
  }

  _, err = r.Seek(int64(80*(offsetHeight-(height%epochLength))), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = epochStart.Deserialize(r)
  if err != nil {
    return 0, err
  }

  var rightBits uint32

  if (height)%epochLength == 0 {
    // if so, check if difficulty adjustment is valid.
    // That whole "controlled supply" thing.
    // calculate diff n based on n-2016 ... n-1
    rightBits = calcDiffAdjustBitcoin(epochStart, prev, p)
  } else { // not a new epoch
    rightBits = epochStart.Bits

    // if on testnet, check for difficulty nerfing
    if p.ReduceMinDifficulty && cur.Timestamp.After(
      prev.Timestamp.Add(p.TargetTimePerBlock*2)) {
      rightBits = p.PowLimitBits // difficulty 1
    }
  }

  return rightBits, nil
}

func LTCDiff (r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  epochLength := int32(p.TargetTimespan / p.TargetTimePerBlock)
  var err error
  var cur, prev, epochStart wire.BlockHeader

  offsetHeight := height - startheight

  // seek to n-1 header
  _, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  // read in n-1
  err = prev.Deserialize(r)
  if err != nil {
    return 0, err
  }

    // seek to curHeight header and read in
  _, err = r.Seek(int64(80*(offsetHeight)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = cur.Deserialize(r)
  if err != nil {
    return 0, err
  }

  _, err = r.Seek(int64(80*(offsetHeight-(height%epochLength))), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = epochStart.Deserialize(r)
  if err != nil {
    return 0, err
  }

  var rightBits uint32

  if (height)%epochLength == 0 {
    // if so, check if difficulty adjustment is valid.
    // That whole "controlled supply" thing.
    // calculate diff n based on n-2016 ... n-1

    // In Litecoin the first epoch recalculates 2015 blocks back
    if height == epochLength {
      _, err = r.Seek(int64(0), os.SEEK_SET)
      if err != nil {
        return 0, err
      }
    } else {
      _, err = r.Seek(int64(offsetHeight - epochLength), os.SEEK_SET)
      if err != nil {
        return 0, err
      }
    }

    err = epochStart.Deserialize(r)
    if err != nil {
      return 0, err
    }

    rightBits = calcDiffAdjustBitcoin(epochStart, prev, p)
  } else { // not a new epoch
    rightBits = epochStart.Bits

    // if on testnet, check for difficulty nerfing
    if p.ReduceMinDifficulty && cur.Timestamp.After(
      prev.Timestamp.Add(p.TargetTimePerBlock*2)) {
      rightBits = p.PowLimitBits // difficulty 1
    }
  }

  return rightBits, nil
}

// Uses Kimoto Gravity Well for difficulty adjustment. Used in VTC, MONA etc
func calcDiffAdjustKGW(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  var minBlocks, maxBlocks int32
  minBlocks = 144
  maxBlocks = 4032

  if height - 1 < minBlocks {
    return p.PowLimitBits, nil
  }

  offsetHeight := height - startheight - 1

  var currentBlock wire.BlockHeader
  var err error

  // seek to n-1 header
  _, err = r.Seek(int64(80*offsetHeight), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  // read in n-1
  err = currentBlock.Deserialize(r)
  if err != nil {
    return 0, err
  }

  lastSolved := currentBlock

  var blocksScanned, actualRate, targetRate int64
  var difficultyAverage, previousDifficultyAverage big.Int
  var rateAdjustmentRatio, eventHorizonDeviation, eventHorizonDeviationFast, eventHorizonDevationSlow float64
  rateAdjustmentRatio = 1

  currentHeight := height - 1

  var i int32

  for i = 1; currentHeight != 1; i++ {
    if i > maxBlocks {
      break
    }

    blocksScanned++

    if i == 1 {
      difficultyAverage = *difficulty.CompactToBig(currentBlock.Bits)
    } else {
      compact := difficulty.CompactToBig(currentBlock.Bits)

      difference  := new(big.Int).Sub(compact, &previousDifficultyAverage)
      difference.Div(difference, big.NewInt(int64(i)))
      difference.Add(difference, &previousDifficultyAverage)
      difficultyAverage = *difference
    }

    previousDifficultyAverage = difficultyAverage

    actualRate = lastSolved.Timestamp.Unix() - currentBlock.Timestamp.Unix()
    targetRate = int64(p.TargetTimePerBlock.Seconds()) * blocksScanned
    rateAdjustmentRatio = 1

    if actualRate < 0 {
      actualRate = 0
    }

    if actualRate != 0 && targetRate != 0 {
      rateAdjustmentRatio = float64(targetRate) / float64(actualRate)
    }

    eventHorizonDeviation = 1 + (0.7084 * math.Pow(float64(blocksScanned)/float64(minBlocks), -1.228))
    eventHorizonDeviationFast = eventHorizonDeviation
    eventHorizonDevationSlow = 1 / eventHorizonDeviation

    if blocksScanned >= int64(minBlocks) && (rateAdjustmentRatio <= eventHorizonDevationSlow || rateAdjustmentRatio >= eventHorizonDeviationFast) {
      break
    }

    if currentHeight < 1 {
      break
    }

    currentHeight--

    _, err = r.Seek(int64(80*(currentHeight - startheight)), os.SEEK_SET)
    if err != nil {
      return 0, err
    }
    // read in n-1
    err = currentBlock.Deserialize(r)
    if err != nil {
      return 0, err
    }
  }

  newTarget := difficultyAverage
  if actualRate != 0 && targetRate != 0 {
    newTarget.Mul(&newTarget, big.NewInt(actualRate))

    newTarget.Div(&newTarget, big.NewInt(targetRate))
  }

  if newTarget.Cmp(p.PowLimit) == 1 {
    newTarget = *p.PowLimit
  }

  return difficulty.BigToCompact(&newTarget), nil
}

func VTCTestDiff (r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  if height < 2116 {
      return LTCDiff(r, height, startheight, p)
  }

  offsetHeight := height - startheight

  // Testnet retargets only every 12 blocks
  if height % 12 != 0 {
      var prev wire.BlockHeader
      var err error

      // seek to n-1 header
      _, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
      if err != nil {
        return 0, err
      }
      // read in n-1
      err = prev.Deserialize(r)
      if err != nil {
        return 0, err
      }

      return prev.Bits, nil
  }

  // Run KGW
  return calcDiffAdjustKGW(r, height, startheight, p)
}



// MainNetParams defines the network parameters for the main Bitcoin network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "5889",
	DNSSeeds: []DNSSeed{
		{"useast1.vtconline.org", true},
		{"vtc.gertjaap.org", true},
		{"vert.idzstad.pl", false},
		{"dnsseed.vertcoin.cc", true},
	},

	// Chain parameters
	GenesisBlock:             &genesisBlock,
	GenesisHash:              &genesisHash,
	PowLimit:                 mainPowLimit,
	PowLimitBits:             0x1e0fffff,
	BIP0034Height:            691488, // 1d0446fe48fdebf4780f544f1de81c2527099da2d09465873475cefe96ab84a1
	BIP0065Height:            691488, // 1d0446fe48fdebf4780f544f1de81c2527099da2d09465873475cefe96ab84a1
	BIP0066Height:            691488, // 1d0446fe48fdebf4780f544f1de81c2527099da2d09465873475cefe96ab84a1
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 840000,
	TargetTimespan:           time.Hour * 24 * 3.5, // 3.5 days
	TargetTimePerBlock:       time.Minute * 2.5,    // 2.5 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
        {      0, newHashFromStr("4d96a915f49d40b1e5c2844d1ee2dccb90013a990ccea12c492d22110489f0c4")},
        {  24200, newHashFromStr("d7ed819858011474c8b0cae4ad0b9bdbb745becc4c386bc22d1220cc5a4d1787")},
        {  65000, newHashFromStr("9e673a69c35a423f736ab66f9a195d7c42f979847a729c0f3cef2c0b8b9d0289")},
        {  84065, newHashFromStr("a904170a5a98109b2909379d9bc03ef97a6b44d5dafbc9084b8699b0cba5aa98")},
        {  228023, newHashFromStr("15c94667a9e941359d2ee6527e2876db1b5e7510a5ded3885ca02e7e0f516b51")},
        {  346992, newHashFromStr("f1714fa4c7990f4b3d472eb22132891ccd3c7ad7208e2d1ab15bde68854fb0ee")},
        {  347269, newHashFromStr("fa1e592b7ea2aa97c5f20ccd7c40f3aaaeb31d1232c978847a79f28f83b6c22a")},
        {  430000, newHashFromStr("2f5703cf7b6f956b84fd49948cbf49dc164cfcb5a7b55903b1c4f53bc7851611")},
        {  516999, newHashFromStr("572ed47da461743bcae526542053e7bc532de299345e4f51d77786f2870b7b28")},
        {  627610, newHashFromStr("6000a787f2d8bb77d4f491a423241a4cc8439d862ca6cec6851aba4c79ccfedc")},
        {  1172000, newHashFromStr("13311f001ad833853d714d1b0425f76004373cb2286a4e5094a811b8a4246147")},
        {  1474747, newHashFromStr("edf23a98cc196888635a01ba4672680df0b7c16eb48146e706b6f2e669974934")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1512, // 95% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016, //
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  1,
			StartTime:  1488326400, // Mar 1st, 2017
			ExpireTime: 1519862400, // Mar 1st, 2018
		},
		DeploymentSegwit: {
			BitNumber:  2,
			StartTime:  1488326400, // Mar 1st, 2017
			ExpireTime: 1519862400, // Mar 1st, 2018
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "vtc", // always bc for main net

	// Address encoding magics
	PubKeyHashAddrID:        0x47, // starts with V
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed), K or L (compressed)

	// not sure for vertcoin
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xAD, 0xE4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xB2, 0x1E}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 28,
}

// RegressionNetParams defines the network parameters for the regression test
// Bitcoin network.  Not to be confused with the test Bitcoin network (version
// 3), this network is sometimes simply called "testnet".
var RegressionNetParams = Params{
	Name:        "regtest",
	Net:         wire.TestNet,
	DefaultPort: "18444",
	DNSSeeds:    []DNSSeed{},

	// Chain parameters
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              &regTestGenesisHash,
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         100,
	BIP0034Height:            100,      // Not active - Permit ver 1 blocks
	BIP0065Height:            100,      // Used by regression tests
	BIP0066Height:            100,      // Used by regression tests
	SubsidyReductionInterval: 150,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,

	// MinDiffReductionTime is from BTC difficulty rules
    // See https://github.com/vertcoin-project/vertcoin-core/blob/master/src/pow.cpp#L66
    // Check if rule changed in https://github.com/vertcoin-project/vertcoin-core/blob/master/src/pow.cpp#L48
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
        {      0, newHashFromStr("2399c0b047ebbbd1650d66867206c97317027b1a1932bc6fc17ce833dc4a85ce")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 108, // 75%  of MinerConfirmationWindow
	MinerConfirmationWindow:       144,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "rvtc", // always bcrt for reg test net

	// Address encoding magics
	PubKeyHashAddrID: 0x4a, // starts with X
	ScriptHashAddrID: 0xc4, // starts with 2
	PrivateKeyID:     0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 28,
}

// TestNet3Params defines the network parameters for the test Bitcoin network
// (version 3).  Not to be confused with the regression test network, this
// network is sometimes simply called "testnet".
var TestNet3Params = Params{
	Name:        "testnet3",
	Net:         wire.TestNet3,
	DefaultPort: "15889",
	DNSSeeds: []DNSSeed{
		{"jlovejoy.mit.edu", true},
		{"gertjaap.ddns.net", true},
		{"fr1.vtconline.org", true},
		{"tvtc.vertcoin.org", true},
	},

	// Chain parameters
    DiffCalcFunction:         VTCTestDiff,
	GenesisBlock:             &testNet3GenesisBlock,
	GenesisHash:              &testNet3GenesisHash,
	PowLimit:                 testNet3PowLimit,
    PoWFunction:              func(b []byte) chainhash.Hash {
                              lyraBytes, _ := lyra2rev2.Sum(b)
                              asChainHash, _ := chainhash.NewHash(lyraBytes)
                              return *asChainHash
                            },
	PowLimitBits:             0x1e0fffff,
	BIP0034Height:            300,  // d6be7cfec4fb1d6a8a94f0a423520a78c97fbdc766cd25f9512adc9249282c2a
	BIP0065Height:            300,  // d6be7cfec4fb1d6a8a94f0a423520a78c97fbdc766cd25f9512adc9249282c2a
	BIP0066Height:            300,  // d6be7cfec4fb1d6a8a94f0a423520a78c97fbdc766cd25f9512adc9249282c2a
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 840000,
	TargetTimespan:           time.Hour * 24 * 3.5, // 3.5 days
	TargetTimePerBlock:       time.Minute * 2.5,    // 2.5 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,

	// MinDiffReductionTime is from BTC difficulty rules
    // See https://github.com/vertcoin-project/vertcoin-core/blob/master/src/pow.cpp#L66
    // Check if rule changed in https://github.com/vertcoin-project/vertcoin-core/blob/master/src/pow.cpp#L48
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{0, newHashFromStr("cee8f24feb7a64c8f07916976aa4855decac79b6741a8ec2e32e2747497ad2c9")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 26, // 52% of MinerConfirmationWindow
	MinerConfirmationWindow:       50,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  1,
			StartTime:  1488326400, // Mar 1st, 2017
			ExpireTime: 1519862400, // Mar 1st, 2018
		},
		DeploymentSegwit: {
			BitNumber:  2,
			StartTime:  1488326400, // Mar 1st, 2017
			ExpireTime: 1519862400, // Mar 1st, 2018
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tvtc", // always tb for test net

	// Address encoding magics
	PubKeyHashAddrID:        0x4a, // starts with W
	ScriptHashAddrID:        0xc4, // starts with 2

	// not sure for vertcoin
	WitnessPubKeyHashAddrID: 0x03, // starts with QW
	WitnessScriptHashAddrID: 0x28, // starts with T7n

	PrivateKeyID:            0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 28,
}

// SimNetParams defines the network parameters for the simulation test Bitcoin
// network.  This network is similar to the normal test network except it is
// intended for private use within a group of individuals doing simulation
// testing.  The functionality is intended to differ in that the only nodes
// which are specifically specified are used to create the network rather than
// following normal discovery rules.  This is important as otherwise it would
// just turn into another public testnet.
var SimNetParams = Params{
	Name:        "simnet",
	Net:         wire.SimNet,
	DefaultPort: "18555",
	DNSSeeds:    []DNSSeed{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
	GenesisBlock:             &simNetGenesisBlock,
	GenesisHash:              &simNetGenesisHash,
	PowLimit:                 simNetPowLimit,
	PowLimitBits:             0x207fffff,
	BIP0034Height:            0, // Always active on simnet
	BIP0065Height:            0, // Always active on simnet
	BIP0066Height:            0, // Always active on simnet
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 75, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       100,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "sb", // always sb for sim net

	// Address encoding magics
	PubKeyHashAddrID:        0x3f, // starts with S
	ScriptHashAddrID:        0x7b, // starts with s
	PrivateKeyID:            0x64, // starts with 4 (uncompressed) or F (compressed)
	WitnessPubKeyHashAddrID: 0x19, // starts with Gg
	WitnessScriptHashAddrID: 0x28, // starts with ?

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x20, 0xb9, 0x00}, // starts with sprv
	HDPublicKeyID:  [4]byte{0x04, 0x20, 0xbd, 0x3a}, // starts with spub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 115, // ASCII for s
}

// SigNetParams defines the network parameters for the default public signet
// Bitcoin network. Not to be confused with the regression test network, this
// network is sometimes simply called "signet" or "taproot signet".
var SigNetParams = CustomSignetParams(
	DefaultSignetChallenge, DefaultSignetDNSSeeds,
)

// CustomSignetParams creates network parameters for a custom signet network
// from a challenge. The challenge is the binary compiled version of the block
// challenge script.
func CustomSignetParams(challenge []byte, dnsSeeds []DNSSeed) Params {
	// The message start is defined as the first four bytes of the sha256d
	// of the challenge script, as a single push (i.e. prefixed with the
	// challenge script length).
	challengeLength := byte(len(challenge))
	hashDouble := chainhash.DoubleHashB(
		append([]byte{challengeLength}, challenge...),
	)

	// We use little endian encoding of the hash prefix to be in line with
	// the other wire network identities.
	net := binary.LittleEndian.Uint32(hashDouble[0:4])
	return Params{
		Name:        "signet",
		Net:         wire.BitcoinNet(net),
		DefaultPort: "38333",
		DNSSeeds:    dnsSeeds,

		// Chain parameters
		GenesisBlock:             &sigNetGenesisBlock,
		GenesisHash:              &sigNetGenesisHash,
		PowLimit:                 sigNetPowLimit,
		PowLimitBits:             0x1e0377ae,
		BIP0034Height:            1,
		BIP0065Height:            1,
		BIP0066Height:            1,
		CoinbaseMaturity:         100,
		SubsidyReductionInterval: 210000,
		TargetTimespan:           time.Hour * 24 * 14, // 14 days
		TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
		RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
		ReduceMinDifficulty:      false,
		MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
		GenerateSupported:        false,

		// Checkpoints ordered from oldest to newest.
		Checkpoints: nil,

		// Consensus rule change deployments.
		//
		// The miner confirmation window is defined as:
		//   target proof of work timespan / target proof of work spacing
		RuleChangeActivationThreshold: 1916, // 95% of 2016
		MinerConfirmationWindow:       2016,
		Deployments: [DefinedDeployments]ConsensusDeployment{
			DeploymentTestDummy: {
				BitNumber:  28,
				StartTime:  1199145601, // January 1, 2008 UTC
				ExpireTime: 1230767999, // December 31, 2008 UTC
			},
			DeploymentCSV: {
				BitNumber:  29,
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			},
			DeploymentSegwit: {
				BitNumber:  29,
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires.
			},
			DeploymentTaproot: {
				BitNumber:  29,
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires.
			},
		},

		// Mempool parameters
		RelayNonStdTxs: false,

		// Human-readable part for Bech32 encoded segwit addresses, as defined in
		// BIP 173.
		Bech32HRPSegwit: "tb", // always tb for test net

		// Address encoding magics
		PubKeyHashAddrID:        0x6f, // starts with m or n
		ScriptHashAddrID:        0xc4, // starts with 2
		WitnessPubKeyHashAddrID: 0x03, // starts with QW
		WitnessScriptHashAddrID: 0x28, // starts with T7n
		PrivateKeyID:            0xef, // starts with 9 (uncompressed) or c (compressed)

		// BIP32 hierarchical deterministic extended key magics
		HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
		HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

		// BIP44 coin type used in the hierarchical deterministic path for
		// address generation.
		HDCoinType: 1,
	}
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")

	// ErrInvalidHDKeyID describes an error where the provided hierarchical
	// deterministic version bytes, or hd key id, is malformed.
	ErrInvalidHDKeyID = errors.New("invalid hd extended key version bytes")
)

var (
	registeredNets       = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs    = make(map[byte]struct{})
	scriptHashAddrIDs    = make(map[byte]struct{})
	bech32SegwitPrefixes = make(map[string]struct{})
	hdPrivToPubKeyIDs    = make(map[[4]byte][]byte)
)

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}

	err := RegisterHDKeyID(params.HDPublicKeyID[:], params.HDPrivateKeyID[:])
	if err != nil {
		return err
	}

	// A valid Bech32 encoded segwit address always has as prefix the
	// human-readable part for the given net followed by '1'.
	bech32SegwitPrefixes[params.Bech32HRPSegwit+"1"] = struct{}{}
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// IsBech32SegwitPrefix returns whether the prefix is a known prefix for segwit
// addresses on any default or registered network.  This is used when decoding
// an address string into a specific address type.
func IsBech32SegwitPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32SegwitPrefixes[prefix]
	return ok
}

// RegisterHDKeyID registers a public and private hierarchical deterministic
// extended key ID pair.
//
// Non-standard HD version bytes, such as the ones documented in SLIP-0132,
// should be registered using this method for library packages to lookup key
// IDs (aka HD version bytes). When the provided key IDs are invalid, the
// ErrInvalidHDKeyID error will be returned.
//
// Reference:
//   SLIP-0132 : Registered HD version bytes for BIP-0032
//   https://github.com/satoshilabs/slips/blob/master/slip-0132.md
func RegisterHDKeyID(hdPublicKeyID []byte, hdPrivateKeyID []byte) error {
	if len(hdPublicKeyID) != 4 || len(hdPrivateKeyID) != 4 {
		return ErrInvalidHDKeyID
	}

	var keyID [4]byte
	copy(keyID[:], hdPrivateKeyID)
	hdPrivToPubKeyIDs[keyID] = hdPublicKeyID

	return nil
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&TestNet3Params)
	mustRegister(&RegressionNetParams)
	mustRegister(&SimNetParams)
}
