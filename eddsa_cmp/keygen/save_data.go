package keygen

import (
	"encoding/hex"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type (
	LocalPreParams struct {
		PaillierSK *paillier.PrivateKey // ski
		NTildei,
		H1i, H2i,
		Alpha, Beta,
		P, Q *big.Int
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		PrivXi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		PubXi *crypto.ECPoint // Xi

		// public keys (Xj = uj*G for each Pj)
		PubXj       []*crypto.ECPoint     // Xj
		PaillierPKs []*paillier.PublicKey // pkj

		// used for test assertions (may be discarded)
		EdDSAPub *crypto.ECPoint // y
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.PubXj = make([]*crypto.ECPoint, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	return
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.PaillierSK.P != nil &&
		preParams.PaillierSK.Q != nil &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalSecrets = sourceData.LocalSecrets
	newData.EdDSAPub = sourceData.EdDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic("BuildLocalSaveDataSubset: unable to find a signer party in the local save data")
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.PubXj[j] = sourceData.PubXj[savedIdx]
		newData.PaillierPKs[j] = sourceData.PaillierPKs[savedIdx]
	}
	return newData
}
