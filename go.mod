module github.com/btcsuite/btcd

require (
	github.com/aead/skein v0.0.0-20160722084837-9365ae6e95d2 // indirect
	github.com/bitgoin/lyra2rev2 v0.0.0-20161212102046-bae9ad2043bb // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/btcsuite/goleveldb v1.0.0
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/btcsuite/winsvc v1.0.0
	github.com/davecgh/go-spew v1.1.1
	github.com/dchest/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/lru v1.0.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
)

go 1.16

replace (
	github.com/btcsuite/btcd => ./
	github.com/btcsuite/btcutil => github.com/vertiond/btcutil v1.0.2-vtc
)