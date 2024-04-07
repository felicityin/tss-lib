package keygen

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/modproof"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"google.golang.org/protobuf/proto"
)

// These messages were generated from Protocol Buffers definitions into eddsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message)(nil),
		(*KGRound3Message)(nil),
	}
)

// ----- //

func NewKGRound1Message(from *tss.PartyID, hash []byte) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound1Message{
		Commitment: hash,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetCommitment())
}

// ----- //

func NewKGRound2Message(
	from *tss.PartyID,
	ssid []byte,
	srid []byte,
	pubX *crypto.ECPoint,
	commitmentA *crypto.ECPoint,
	u []byte,
	paillierPK *paillier.PublicKey,
	pedPK *paillier.PedPubKey,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound2Message{
		Ssid:        ssid,
		Srid:        srid,
		PublicXX:    pubX.X().Bytes(),
		PublicXY:    pubX.Y().Bytes(),
		CommitmentX: commitmentA.X().Bytes(),
		CommitmentY: commitmentA.Y().Bytes(),
		U:           u,
		PaillierN:   paillierPK.N.Bytes(),
		PedersenS:   pedPK.S.Bytes(),
		PedersenT:   pedPK.T.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetPublicXX()) &&
		common.NonEmptyBytes(m.GetPublicXY()) &&
		common.NonEmptyBytes(m.GetCommitmentX()) &&
		common.NonEmptyBytes(m.GetCommitmentY()) &&
		common.NonEmptyBytes(m.GetSrid()) &&
		common.NonEmptyBytes(m.GetSsid()) &&
		common.NonEmptyBytes(m.GetU())
}

func (m *KGRound2Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound2Message) UnmarshalPedersenPK() *paillier.PedPubKey {
	return &paillier.PedPubKey{
		S: new(big.Int).SetBytes(m.GetPedersenS()),
		T: new(big.Int).SetBytes(m.GetPedersenT()),
	}
}

func (m *KGRound2Message) UnmarshalPubXj(ec elliptic.Curve) (*crypto.ECPoint, error) {
	publicX, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetPublicXX()),
		new(big.Int).SetBytes(m.GetPublicXY()),
	)
	if err != nil {
		return nil, err
	}
	return publicX, nil
}

func (m *KGRound2Message) UnmarshalPayload(ec elliptic.Curve) (*CmpKeyGenerationPayload, error) {
	commitedA, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetCommitmentX()),
		new(big.Int).SetBytes(m.GetCommitmentY()),
	)
	if err != nil {
		return nil, err
	}

	return &CmpKeyGenerationPayload{
		commitedA: commitedA,
		ssid:      m.GetSsid(),
		srid:      m.GetSrid(),
		u:         m.GetU(),
	}, nil
}

// ----- //

func NewKGRound3Message(
	from *tss.PartyID,
	schProof []byte,
	modProof *modproof.ProofMod,
	prmProof []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	modProofBzs := modProof.Bytes()
	content := &KGRound3Message{
		SchProof: schProof,
		ModProof: modProofBzs[:],
		PrmProof: prmProof,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetSchProof())
}

func (m *KGRound3Message) UnmarshalSchProof() *big.Int {
	return new(big.Int).SetBytes(m.GetSchProof())
}

func (m *KGRound3Message) UnmarshalModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetModProof())
}

func (m *KGRound3Message) UnmarshalPrmProof() (*paillierzkproof.RingPederssenParameterMessage, error) {
	prmProof := &paillierzkproof.RingPederssenParameterMessage{}
	if err := proto.Unmarshal(m.GetPrmProof(), prmProof); err != nil {
		return nil, err
	}
	return prmProof, nil
}
