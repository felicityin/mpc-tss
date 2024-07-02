package sign

import (
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	"github.com/felicityin/mpc-tss/crypto/affproof"
	"github.com/felicityin/mpc-tss/crypto/encproof"
	"github.com/felicityin/mpc-tss/crypto/logproof"
	"github.com/felicityin/mpc-tss/tss"
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
		(*SignRound4Message)(nil),
	}
)

func NewSignRound1Message1(
	from *tss.PartyID,
	kCiphertext *big.Int,
	gammaCiphertext *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message1{
		KCiphertext:     kCiphertext.Bytes(),
		GammaCiphertext: gammaCiphertext.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return common.NonEmptyBytes(m.GetKCiphertext()) && common.NonEmptyBytes(m.GetGammaCiphertext())
}

func (m *SignRound1Message1) UnmarshalK() *big.Int {
	return (new(big.Int).SetBytes(m.GetKCiphertext()))
}

func (m *SignRound1Message1) UnmarshalGamma() *big.Int {
	return (new(big.Int).SetBytes(m.GetGammaCiphertext()))
}

// ----- //

func NewSignRound1Message2(
	to, from *tss.PartyID,
	encProof *encproof.EncryptRangeMessage,
) (tss.ParsedMessage, error) {
	encProofBytes, err := proto.Marshal(encProof)
	if err != nil {
		common.Logger.Errorf("marshal enc proof failed: %s", err)
		return nil, fmt.Errorf("marshal enc proof failed: %s", err)
	}

	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &SignRound1Message2{
		EncProof: encProofBytes,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
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
	Gamma *crypto.ECPoint,
	D []byte,
	F *big.Int,
	Dhat []byte,
	Fhat *big.Int,
	psiProof *affproof.PaillierAffAndGroupRangeMessage,
	psiHatProof *affproof.PaillierAffAndGroupRangeMessage,
	logProof *logproof.LogStarMessage,
) (tss.ParsedMessage, error) {
	GammaBytes, err := Gamma.MarshalJSON()
	if err != nil {
		common.Logger.Errorf("marshal gamma err: %s", err.Error())
		return nil, fmt.Errorf("marshal gamma err: %s", err.Error())
	}
	psiProofBytes, err := proto.Marshal(psiProof)
	if err != nil {
		common.Logger.Errorf("marshal affg proof err: %s", err.Error())
		return nil, fmt.Errorf("marshal affg proof err: %s", err.Error())
	}
	psiHahtProofBytes, err := proto.Marshal(psiHatProof)
	if err != nil {
		common.Logger.Errorf("marshal affg_hat proof err: %s", err.Error())
		return nil, fmt.Errorf("marshal affg_hat proof err: %s", err.Error())
	}
	logProofBytes, err := proto.Marshal(logProof)
	if err != nil {
		common.Logger.Errorf("marshal log proof err: %s", err)
		return nil, fmt.Errorf("marshal log proof err: %s", err.Error())
	}

	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &SignRound2Message{
		BigGamma:     GammaBytes,
		D:            D,
		F:            F.Bytes(),
		DHat:         Dhat,
		FHat:         Fhat.Bytes(),
		AffgProof:    psiProofBytes,
		AffgHatProof: psiHahtProofBytes,
		LogProof:     logProofBytes,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.BigGamma) &&
		common.NonEmptyBytes(m.D) &&
		common.NonEmptyBytes(m.F) &&
		common.NonEmptyBytes(m.DHat) &&
		common.NonEmptyBytes(m.FHat) &&
		common.NonEmptyBytes(m.AffgProof) &&
		common.NonEmptyBytes(m.AffgHatProof) &&
		common.NonEmptyBytes(m.LogProof)
}

func (m *SignRound2Message) UnmarshalGamma() (*crypto.ECPoint, error) {
	pt, err := crypto.UnmarshalJSONPoint(m.GetBigGamma())
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (m *SignRound2Message) UnmarshalAffgProof() (*affproof.PaillierAffAndGroupRangeMessage, error) {
	affgProof := &affproof.PaillierAffAndGroupRangeMessage{}
	if err := proto.Unmarshal(m.GetAffgProof(), affgProof); err != nil {
		return nil, err
	}
	return affgProof, nil
}

func (m *SignRound2Message) UnmarshalAffgHatProof() (*affproof.PaillierAffAndGroupRangeMessage, error) {
	affgHatProof := &affproof.PaillierAffAndGroupRangeMessage{}
	if err := proto.Unmarshal(m.GetAffgHatProof(), affgHatProof); err != nil {
		return nil, err
	}
	return affgHatProof, nil
}

func (m *SignRound2Message) UnmarshalLogProof() (*logproof.LogStarMessage, error) {
	logProof := &logproof.LogStarMessage{}
	if err := proto.Unmarshal(m.GetLogProof(), logProof); err != nil {
		return nil, err
	}
	return logProof, nil
}

// ----- //

func NewSignRound3Message(
	to, from *tss.PartyID,
	delta *big.Int,
	Delta *crypto.ECPoint,
	logProof *logproof.LogStarMessage,
) (tss.ParsedMessage, error) {
	logProofBytes, err := proto.Marshal(logProof)
	if err != nil {
		common.Logger.Errorf("marshal log proof err: %s", err)
		return nil, fmt.Errorf("marshal log proof err: %s", err.Error())
	}
	deltaBytes, err := Delta.MarshalJSON()
	if err != nil {
		common.Logger.Errorf("marshal gamma err: %s", err.Error())
		return nil, fmt.Errorf("marshal gamma err: %s", err.Error())
	}

	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &SignRound3Message{
		Delta:    delta.Bytes(),
		BigDelta: deltaBytes,
		LogProof: logProofBytes,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.BigDelta) &&
		common.NonEmptyBytes(m.Delta) &&
		common.NonEmptyBytes(m.LogProof)
}

func (m *SignRound3Message) UnmarshalDelta() *big.Int {
	return new(big.Int).SetBytes(m.GetDelta())
}

func (m *SignRound3Message) UnmarshalBigDelta() (*crypto.ECPoint, error) {
	pt, err := crypto.UnmarshalJSONPoint(m.GetBigDelta())
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (m *SignRound3Message) UnmarshalLogProof() (*logproof.LogStarMessage, error) {
	logProof := &logproof.LogStarMessage{}
	if err := proto.Unmarshal(m.GetLogProof(), logProof); err != nil {
		return nil, err
	}
	return logProof, nil
}

// ----- //

func NewSignRound4Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound4Message{
		Sigma: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Sigma)
}

func (m *SignRound4Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.GetSigma())
}
