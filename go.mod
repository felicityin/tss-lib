module github.com/bnb-chain/tss-lib/v2

go 1.16

require (
	github.com/agl/ed25519 v0.0.0-20200225211852-fd4d107ace12
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.3
	github.com/felicityin/crypto-go v0.0.0-20240406103822-9688a90b82bf // indirect
	github.com/getamis/alice v1.0.3
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/ipfs/go-log v1.0.5
	github.com/otiai10/primes v0.0.0-20210501021515-f1b2be525a11
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.18.0
	google.golang.org/protobuf v1.33.0
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
