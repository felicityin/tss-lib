package paillier

import "math/big"

type (
	PedPubKey struct {
		N *big.Int
		S *big.Int
		T *big.Int
	}

	PedPrivKey struct {
		PedPubKey
		LambdaN *big.Int
		Euler   *big.Int
	}
)
