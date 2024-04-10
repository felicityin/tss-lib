// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
)

func GenerateNTildei(rand io.Reader, safePrimes [2]*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if safePrimes[0] == nil || safePrimes[1] == nil {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: needs two primes, got %v", safePrimes)
	}
	if !safePrimes[0].ProbablyPrime(30) || !safePrimes[1].ProbablyPrime(30) {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: expected two primes")
	}
	NTildei = new(big.Int).Mul(safePrimes[0], safePrimes[1])
	h1 := common.GetRandomGeneratorOfTheQuadraticResidue(rand, NTildei)
	h2 := common.GetRandomGeneratorOfTheQuadraticResidue(rand, NTildei)
	return NTildei, h1, h2, nil
}

func Xor(bigArray, smallArray []byte) []byte {
	if len(bigArray) < len(smallArray) {
		return Xor(smallArray, bigArray)
	}
	result := make([]byte, len(bigArray))
	for i := 0; i < len(smallArray); i++ {
		result[i] = bigArray[i] ^ smallArray[i]
	}
	for i := len(smallArray); i < len(bigArray); i++ {
		result[i] = bigArray[i]
	}
	return result
}
