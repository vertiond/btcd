// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
var genesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
                0x00, 0x02, 0xe7, 0x03, 0x41, 0x30, 0x31, 0x2f,
                0x30, 0x39, 0x2f, 0x32, 0x30, 0x31, 0x34, 0x20,
                0x47, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x79, 0x20,
                0x74, 0x6f, 0x20, 0x48, 0x65, 0x6c, 0x70, 0x20,
                0x69, 0x6e, 0x20, 0x44, 0x69, 0x73, 0x70, 0x6f,
                0x73, 0x61, 0x6c, 0x20, 0x6f, 0x66, 0x20, 0x53,
                0x79, 0x72, 0x69, 0x61, 0x6e, 0x20, 0x43, 0x68,
                0x65, 0x6d, 0x69, 0x63, 0x61, 0x6c, 0x20, 0x57,
                0x65, 0x61, 0x70, 0x6f, 0x6e, 0x73,
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value: 0x12a05f200,
			PkScript: []byte{
				0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, /* |A.g....U| */
				0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, /* |H'.g..q0| */
				0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, /* |..\..(.9| */
				0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, /* |..yb...a| */
				0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, /* |..I..?L.| */
				0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, /* |8..U....| */
				0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, /* |..\8M...| */
				0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, /* |.W.Lp+k.| */
				0x1d, 0x5f, 0xac, /* |._.| */
			},
		},
	},
	LockTime: 0,
}

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block).
var genesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0xc4, 0xf0, 0x89, 0x04, 0x11, 0x22, 0x2d, 0x49,
    0x2c, 0xa1, 0xce, 0x0c, 0x99, 0x3a, 0x01, 0x90,
    0xcb, 0xdc, 0xe2, 0x1e, 0x4d, 0x84, 0xc2, 0xe5,
    0xb1, 0x40, 0x9d, 0xf4, 0x15, 0xa9, 0x96, 0x4d,
})

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
var genesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0xe7, 0x23, 0x01, 0xfc, 0x49, 0x32, 0x3e, 0xe1,
    0x51, 0xcf, 0x10, 0x48, 0x23, 0x0f, 0x03, 0x2c,
    0xa5, 0x89, 0x75, 0x3b, 0xa7, 0x08, 0x62, 0x22,
    0xa5, 0xc0, 0x23, 0xe3, 0xa0, 0x8c, 0xf3, 0x4a,
})

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var genesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: genesisMerkleRoot,        // 4af38ca0e323c0a5226208a73b7589a52c030f234810cf51e13e3249fc0123e7
		Timestamp:  time.Unix(1389311371, 0), // 2014-01-09 23:49:31 +0000 UTC
		Bits:       0x1e0ffff0,               //
		Nonce:      5749262,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// regTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var regTestGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0xce, 0x85, 0x4a, 0xdc, 0x33, 0xe8, 0x7c, 0xc1,
    0x6f, 0xbc, 0x32, 0x19, 0x1a, 0x7b, 0x02, 0x17,
    0x73, 0xc9, 0x06, 0x72, 0x86, 0x66, 0x0d, 0x65,
    0xd1, 0xbb, 0xeb, 0x47, 0xb0, 0xc0, 0x99, 0x23,
})

// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var regTestGenesisMerkleRoot = genesisMerkleRoot

// regTestGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the regression test network.
var regTestGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: regTestGenesisMerkleRoot, // 4af38ca0e323c0a5226208a73b7589a52c030f234810cf51e13e3249fc0123e7
		Timestamp:  time.Unix(1296688602, 0), // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      2,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// testNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var testNet3GenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0xc9, 0xd2, 0x7a, 0x49, 0x47, 0x27, 0x2e, 0xe3,
    0xc2, 0x8e, 0x1a, 0x74, 0xb6, 0x79, 0xac, 0xec,
    0x5d, 0x85, 0xa4, 0x6a, 0x97, 0x16, 0x79, 0xf0,
    0xc8, 0x64, 0x7a, 0xeb, 0x4f, 0xf2, 0xe8, 0xce,
})

// testNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var testNet3GenesisMerkleRoot = genesisMerkleRoot

// testNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet3GenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},          // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNet3GenesisMerkleRoot, // 4af38ca0e323c0a5226208a73b7589a52c030f234810cf51e13e3249fc0123e7
		Timestamp:  time.Unix(1481291250, 0),  // 2016-12-09 13:47:30 +0000 UTC
		Bits:       0x1e0ffff0,                //
		Nonce:      915027,                    //
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// simNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var simNetGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0xf6, 0x7a, 0xd7, 0x69, 0x5d, 0x9b, 0x66, 0x2a,
	0x72, 0xff, 0x3d, 0x8e, 0xdb, 0xbb, 0x2d, 0xe0,
	0xbf, 0xa6, 0x7b, 0x13, 0x97, 0x4b, 0xb9, 0x91,
	0x0d, 0x11, 0x6d, 0x5c, 0xbd, 0x86, 0x3e, 0x68,
})

// simNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var simNetGenesisMerkleRoot = genesisMerkleRoot

// simNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the simulation test network.
var simNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: simNetGenesisMerkleRoot,  // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1401292357, 0), // 2014-05-28 15:52:37 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      2,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// sigNetGenesisHash is the hash of the first block in the block chain for the
// signet test network.
var sigNetGenesisHash = chainhash.Hash{
	0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4,
	0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
	0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25,
	0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
}

// sigNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the signet test network. It is the same as the merkle root for
// the main network.
var sigNetGenesisMerkleRoot = genesisMerkleRoot

// sigNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the signet test network.
var sigNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: sigNetGenesisMerkleRoot,  // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1598918400, 0), // 2020-09-01 00:00:00 +0000 UTC
		Bits:       0x1e0377ae,               // 503543726 [00000377ae000000000000000000000000000000000000000000000000000000]
		Nonce:      52613770,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}
