package keygen

import (
	"errors"
	"math/big"
	"strconv"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// round 1 represents round 1 of the keygen part of the EDDSA TSS spec
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 1 already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("party: %d, round_1 start", i)

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid

	round.save.PrivXi = common.GetRandomPositiveInt(round.PartialKeyRand(), round.Params().EC().Params().N)
	round.save.PubXi = crypto.ScalarBaseMult(round.EC(), round.save.PrivXi)
	round.save.PubXj[i] = round.save.PubXi

	round.temp.tau = common.GetRandomPositiveInt(round.PartialKeyRand(), round.Params().EC().Params().N)
	round.temp.commitedA = crypto.ScalarBaseMult(round.EC(), round.temp.tau)

	round.temp.u, _ = common.GetRandomBytes(round.Rand(), 32)
	round.temp.srid, _ = common.GetRandomBytes(round.Rand(), 32)

	ids := round.Parties().IDs().Keys()
	round.save.Ks = ids
	round.save.ShareID = ids[i]

	hash := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(i)),
		round.temp.srid,
		round.save.PubXi.X().Bytes(),
		round.save.PubXi.Y().Bytes(),
		round.temp.commitedA.X().Bytes(),
		round.temp.commitedA.Y().Bytes(),
		round.temp.u,
	)

	common.Logger.Infof("party: %d, round_1 broadcast", i)

	// BROADCAST commitments
	{
		msg := NewKGRound1Message(round.PartyID(), hash)
		round.temp.kgRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.kgRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
