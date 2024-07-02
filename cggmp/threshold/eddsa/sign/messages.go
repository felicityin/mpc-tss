package sign

import (
	"crypto/elliptic"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/encproof"
	"github.com/felicityin/mpc-tss/crypto/logproof"
	"github.com/felicityin/mpc-tss/tss"

	"google.golang.org/protobuf/proto"
)

// These messages were generated from Protocol Buffers definitions into eddsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message1)(nil),
		(*SignRound1Message2)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
	}
)

func NewSignRound1Message1(
	from *tss.PartyID,
	kCiphertext *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message1{
		BigK: kCiphertext.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return common.NonEmptyBytes(m.GetBigK())
}

func (m *SignRound1Message1) UnmarshalK() *big.Int {
	return (new(big.Int).SetBytes(m.GetBigK()))
}

// ----- //

func NewSignRound1Message2(
	to, from *tss.PartyID,
	encProof []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &SignRound1Message2{
		EncProof: encProof,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message2) ValidateBasic() bool {
	return common.NonEmptyBytes(m.GetEncProof())
}

func (m *SignRound1Message2) UnmarshalEncProof() (*encproof.EncryptRangeMessage, error) {
	encProof := &encproof.EncryptRangeMessage{}
	if err := proto.Unmarshal(m.GetEncProof(), encProof); err != nil {
		return nil, err
	}
	return encProof, nil
}

// ----- //

func NewSignRound2Message(
	to, from *tss.PartyID,
	R *crypto.ECPoint,
	logProof []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &SignRound2Message{
		RX:       R.X().Bytes(),
		RY:       R.Y().Bytes(),
		LogProof: logProof,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.LogProof) &&
		common.NonEmptyBytes(m.RX) &&
		common.NonEmptyBytes(m.RY)
}

func (m *SignRound2Message) UnmarshalR(ec elliptic.Curve) (*crypto.ECPoint, error) {
	R, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetRX()),
		new(big.Int).SetBytes(m.GetRY()),
	)
	if err != nil {
		return nil, err
	}
	return R, nil
}

func (m *SignRound2Message) UnmarshalLogProof(ec elliptic.Curve) (*logproof.LogStarMessage, error) {
	logProof := &logproof.LogStarMessage{}
	if err := proto.Unmarshal(m.GetLogProof(), logProof); err != nil {
		return nil, err
	}
	return logProof, nil
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		Sigma: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Sigma)
}

func (m *SignRound3Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.GetSigma())
}
