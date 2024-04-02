package keygen

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 4 already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_4 start", i)

	for j, msg := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}

		common.Logger.Debugf("round_4 calc challenge")
		challenge := common.RejectionSample(
			round.EC().Params().N,
			common.SHA512_256i_TAGGED(
				append(round.temp.ssid, round.temp.srid...),
				big.NewInt(int64(j)),
				round.save.PubXj[j].X(),
				round.save.PubXj[j].Y(),
				round.temp.payload[j].commitedA.X(),
				round.temp.payload[j].commitedA.Y(),
			),
		)

		common.Logger.Debugf("round_4 calc proof")
		proof := schnorr.Proof{Proof: msg.Content().(*KGRound3Message).Unmarshal()}

		common.Logger.Debugf("round_4 verify proof")
		if !proof.Verify(round.temp.payload[j].commitedA, round.save.PubXj[j], challenge) {
			common.Logger.Errorf("verify schnorr proof failed, party: %d", j)
			return round.WrapError(errors.New("verify schnorr proof failed"))
		}
	}

	// Compute and SAVE the EdDSA public key
	eddsaPubKey := round.save.PubXi
	var err error
	for j, pubx := range round.save.PubXj {
		if j == i {
			continue
		}
		eddsaPubKey, err = eddsaPubKey.Add(pubx)
		if err != nil {
			common.Logger.Errorf("calc pubkey failed, party: %d", j)
			return round.WrapError(errors.New("calc pubkey failed"))
		}
	}
	round.save.EdDSAPub = eddsaPubKey

	common.Logger.Infof("party: %d, round_4 save", i)
	round.end <- round.save

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
