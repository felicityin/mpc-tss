package auxiliary

import (
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"

	"github.com/felicityin/mpc-tss/common"
	zkPaillier "github.com/felicityin/mpc-tss/crypto/alice/zkproof/paillier"
	"github.com/felicityin/mpc-tss/crypto/facproof"
	"github.com/felicityin/mpc-tss/crypto/modproof"
	"github.com/felicityin/mpc-tss/crypto/paillier"
	"github.com/felicityin/mpc-tss/crypto/prmproof"
	"github.com/felicityin/mpc-tss/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*AuxRound1Message)(nil),
		(*AuxRound2Message)(nil),
		(*AuxRound3Message)(nil),
	}
)

// ----- //

func NewAuxRound1Message(from *tss.PartyID, hash []byte) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &AuxRound1Message{
		Hash: hash,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *AuxRound1Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetHash())
}

// ----- //

func NewAuxRound2Message(
	from *tss.PartyID,
	ssid []byte,
	srid []byte,
	paillierPK *paillier.PublicKey,
	pedPK *zkPaillier.PederssenOpenParameter,
	prmProof []byte,
	rho []byte,
	u []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &AuxRound2Message{
		Ssid:      ssid,
		Srid:      srid,
		PaillierN: paillierPK.N.Bytes(),
		PedersenS: pedPK.S.Bytes(),
		PedersenT: pedPK.T.Bytes(),
		PrmProof:  prmProof,
		Rho:       rho,
		U:         u,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *AuxRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetSsid()) &&
		common.NonEmptyBytes(m.GetSrid()) &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetPedersenS()) &&
		common.NonEmptyBytes(m.GetPedersenT()) &&
		common.NonEmptyBytes(m.GetPrmProof()) &&
		common.NonEmptyBytes(m.GetRho()) &&
		common.NonEmptyBytes(m.GetU())
}

func (m *AuxRound2Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *AuxRound2Message) UnmarshalPedersenPK() *zkPaillier.PederssenOpenParameter {
	return &zkPaillier.PederssenOpenParameter{
		N: new(big.Int).SetBytes(m.GetPaillierN()),
		S: new(big.Int).SetBytes(m.GetPedersenS()),
		T: new(big.Int).SetBytes(m.GetPedersenT()),
	}
}

func (m *AuxRound2Message) UnmarshalPrmProof() (*prmproof.RingPederssenParameterMessage, error) {
	prmProof := &prmproof.RingPederssenParameterMessage{}
	if err := proto.Unmarshal(m.GetPrmProof(), prmProof); err != nil {
		return nil, err
	}
	return prmProof, nil
}

// ----- //

func NewAuxRound3Message(
	to, from *tss.PartyID,
	facProof *facproof.NoSmallFactorMessage,
	modProof *modproof.PaillierBlumMessage,
) (tss.ParsedMessage, error) {
	facProofBytes, err := proto.Marshal(facProof)
	if err != nil {
		common.Logger.Errorf("marshal fac proof error: %s", err)
		return nil, fmt.Errorf("marshal fac proof error: %s", err)
	}
	modProofBytes, err := proto.Marshal(modProof)
	if err != nil {
		common.Logger.Errorf("marshal fac proof error: %s", err)
		return nil, fmt.Errorf("marshal fac proof error: %s", err)
	}

	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &AuxRound3Message{
		FacProof: facProofBytes,
		ModProof: modProofBytes,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *AuxRound3Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetFacProof())
}

func (m *AuxRound3Message) UnmarshalFacProof() (*facproof.NoSmallFactorMessage, error) {
	facProof := &facproof.NoSmallFactorMessage{}
	if err := proto.Unmarshal(m.GetFacProof(), facProof); err != nil {
		return nil, err
	}
	return facProof, nil
}

func (m *AuxRound3Message) UnmarshalModProof() (*modproof.PaillierBlumMessage, error) {
	modProof := &modproof.PaillierBlumMessage{}
	if err := proto.Unmarshal(m.GetModProof(), modProof); err != nil {
		return nil, err
	}
	return modProof, nil
}
