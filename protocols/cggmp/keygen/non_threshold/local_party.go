package keygen

import (
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto"
	save "github.com/felicityin/mpc-tss/protocols/cggmp/keygen"
	"github.com/felicityin/mpc-tss/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		data save.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *save.LocalPartySaveData
	}

	localMessageStore struct {
		kgRound1Messages,
		kgRound2Messages,
		kgRound3Messages []tss.ParsedMessage
	}

	// temp data (thrown away after keygen)
	localTempData struct {
		localMessageStore

		chainCode []byte // 32-bytes

		// ZKP Schnorr
		tau       *big.Int
		commitedA *crypto.ECPoint

		// Echo broadcast and random oracle data seed
		srid []byte
		u    []byte

		payload []*CmpKeyGenerationPayload

		ssid      []byte
		ssidNonce *big.Int

		V [][]byte
	}
)

type CmpKeyGenerationPayload struct {
	// Schnorr ZKP
	commitedA *crypto.ECPoint

	// Echo broadcast and random oracle data seed
	ssid []byte
	srid []byte
	u    []byte
}

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- *save.LocalPartySaveData,
) tss.Party {
	partyCount := params.PartyCount()
	data := save.NewLocalPartySaveData(partyCount)
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}

	// msgs init
	p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.payload = make([]*CmpKeyGenerationPayload, partyCount)
	p.temp.V = make([][]byte, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *KGRound1Message:
		p.temp.kgRound1Messages[fromPIdx] = msg
	case *KGRound2Message:
		p.temp.kgRound2Messages[fromPIdx] = msg
	case *KGRound3Message:
		p.temp.kgRound3Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}

func (p *LocalParty) SetNewSecretX(x *big.Int) {
	p.data.PrivXi = x
}
