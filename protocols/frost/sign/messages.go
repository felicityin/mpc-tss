package sign

import (
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*SignRound2Message)(nil),
	}
)

func NewSignRound1Message(
	from *tss.PartyID,
	D *crypto.ECPoint,
	E *crypto.ECPoint,
) (tss.ParsedMessage, error) {
	d, err := D.MarshalJSON()
	if err != nil {
		return nil, err
	}
	e, err := E.MarshalJSON()
	if err != nil {
		return nil, err
	}

	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		D: d,
		E: e,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *SignRound1Message) ValidateBasic() bool {
	return common.NonEmptyBytes(m.GetD()) && common.NonEmptyBytes(m.GetE())
}

func (m *SignRound1Message) UnmarshalD() (*crypto.ECPoint, error) {
	pt, err := crypto.UnmarshalJSONPoint(m.GetD())
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (m *SignRound1Message) UnmarshalE() (*crypto.ECPoint, error) {
	pt, err := crypto.UnmarshalJSONPoint(m.GetE())
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// ----- //

func NewSignRound2Message(
	from *tss.PartyID,
	z *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound2Message{
		Si: z.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetSi())
}

func (m *SignRound2Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.GetSi())
}
