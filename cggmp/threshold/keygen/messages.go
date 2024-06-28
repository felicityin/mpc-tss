package keygen

import (
	"math/big"

	"mpc_tss/common"
	"mpc_tss/crypto"
	cmt "mpc_tss/crypto/commitments"
	"mpc_tss/crypto/vss"
	"mpc_tss/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*TKgRound1Message)(nil),
		(*TKgRound2Message1)(nil),
		(*TKgRound2Message2)(nil),
		(*TKgRound3Message)(nil),
	}
)

// ----- //

func NewKGRound1Message(from *tss.PartyID, hash []byte, polyCommitment cmt.HashCommitment) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &TKgRound1Message{
		Hash:           hash,
		PolyCommitment: polyCommitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *TKgRound1Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetHash()) && common.NonEmptyBytes(m.GetPolyCommitment())
}

func (m *TKgRound1Message) UnmarshalPolyCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetPolyCommitment())
}

// ----- //

func NewKGRound2Message1(
	from *tss.PartyID,
	ssid []byte,
	srid []byte,
	deCommitment cmt.HashDeCommitment,
	commitmentA *crypto.ECPoint,
	u []byte,
	chainCode []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	com, _ := commitmentA.MarshalJSON()
	content := &TKgRound2Message1{
		Ssid:          ssid,
		Srid:          srid,
		PolyG:         common.BigIntsToBytes(deCommitment),
		SchCommitment: com,
		U:             u,
		ChainCode:     chainCode,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *TKgRound2Message1) ValidateBasic() bool {
	return m != nil &&
		len(m.GetPolyG()) > 0 &&
		common.NonEmptyBytes(m.GetPolyG()[0]) &&
		common.NonEmptyBytes(m.GetSchCommitment()) &&
		common.NonEmptyBytes(m.GetSrid()) &&
		common.NonEmptyBytes(m.GetSsid()) &&
		common.NonEmptyBytes(m.GetU())
}

func (m *TKgRound2Message1) UnmarshalSchCommitment() (*crypto.ECPoint, error) {
	commitedA, err := crypto.UnmarshalJSONPoint(m.GetSchCommitment())
	if err != nil {
		return nil, err
	}
	return commitedA, nil
}

func (m *TKgRound2Message1) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetPolyG()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewKGRound2Message2(
	to, from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &TKgRound2Message2{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *TKgRound2Message2) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetShare())
}

func (m *TKgRound2Message2) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
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
	content := &TKgRound3Message{
		SchProof: schProof,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *TKgRound3Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetSchProof())
}

func (m *TKgRound3Message) UnmarshalSchProof() *big.Int {
	return new(big.Int).SetBytes(m.GetSchProof())
}
