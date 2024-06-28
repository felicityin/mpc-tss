package keygen

import (
	"crypto/elliptic"
	"math/big"

	"mpc_tss/common"
	"mpc_tss/crypto"
	"mpc_tss/tss"
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
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound3Message{
		SchProof: schProof,
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
