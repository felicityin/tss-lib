package keygen

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/getamis/alice/crypto/zkproof/paillier"
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

		contextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))

		common.Logger.Debugf("round_4 get proof")

		schProof := schnorr.Proof{Proof: msg.Content().(*KGRound3Message).UnmarshalSchProof()}

		modProof, err := msg.Content().(*KGRound3Message).UnmarshalModProof()
		if err != nil {
			common.Logger.Errorf("unmarshal mod proof failed, party: %d", j)
			return round.WrapError(errors.New("unmarshal mod proof failed"))
		}

		prmProof, err := msg.Content().(*KGRound3Message).UnmarshalPrmProof()
		if err != nil {
			common.Logger.Errorf("unmarshal prm proof failed, party: %d", j)
			return round.WrapError(errors.New("unmarshal prm proof failed"))
		}

		common.Logger.Debugf("round_4 verify proof")

		if !schProof.Verify(round.temp.payload[j].commitedA, round.save.PubXj[j], challenge) {
			common.Logger.Errorf("schnorr proof verify failed, party: %d", j)
			return round.WrapError(errors.New("schnorr proof verify failed"))
		}

		if ok := modProof.Verify(contextJ, round.save.PaillierPKs[j].N); !ok {
			common.Logger.Errorf("mod proof verify failed, party: %d", j)
			return round.WrapError(errors.New("mod proof verify failed"))
		}

		if err := round.verifyPrmPubkeys(j, prmProof); err != nil {
			return round.WrapError(err)
		}

		if err := prmProof.Verify(contextJ); err != nil {
			common.Logger.Errorf("verify prm proof failed, party: %d", j)
			return round.WrapError(err)
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
			return round.WrapError(err)
		}
	}
	round.save.EdDSAPub = eddsaPubKey

	common.Logger.Infof("party: %d, round_4 save", i)
	round.end <- round.save

	return nil
}

func (round *round4) verifyPrmPubkeys(j int, msg *paillier.RingPederssenParameterMessage) error {
	n := new(big.Int).SetBytes(msg.N)
	s := new(big.Int).SetBytes(msg.S)
	t := new(big.Int).SetBytes(msg.T)

	if n.Cmp(round.save.RingPedersenPKs[j].N) != 0 {
		common.Logger.Errorf("msg.N != save.N, party: %d, msg.N = %d, save.N = %d", j, n, round.save.RingPedersenPKs[j].N)
		return errors.New("msg.N != save.N")
	}

	if s.Cmp(round.save.RingPedersenPKs[j].S) != 0 {
		common.Logger.Errorf("msg.S != save.S, party: %d", j)
		return errors.New("msg.S != save.S")
	}

	if t.Cmp(round.save.RingPedersenPKs[j].T) != 0 {
		common.Logger.Errorf("msg.T != save.T, party: %d", j)
		return errors.New("msg.T != save.T")
	}
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
