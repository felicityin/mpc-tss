package auxiliary

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/felicityin/mpc-tss/common"
	"github.com/felicityin/mpc-tss/crypto/paillier"
	"github.com/felicityin/mpc-tss/crypto/prmproof"
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
		data LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *LocalPartySaveData
	}

	localMessageStore struct {
		auxRound1Messages,
		auxRound2Messages,
		auxRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		prmProof *prmproof.RingPederssenParameterMessage

		// Echo broadcast and random oracle data seed
		srid []byte
		u    []byte
		rho  []byte

		ssid      []byte
		ssidNonce *big.Int

		V [][]byte
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- *LocalPartySaveData,
) tss.Party {
	partyCount := params.PartyCount()
	data := NewLocalPartySaveData(partyCount)
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}

	// msgs init
	p.temp.auxRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.auxRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.auxRound3Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.V = make([][]byte, partyCount)
	return p
}

func (p *LocalParty) PaillierSK() *paillier.PrivateKey {
	return p.data.PaillierSK
}

func (p *LocalParty) SetPaillierSK(sk *paillier.PrivateKey) {
	p.data.PaillierSK = sk
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
	case *AuxRound1Message:
		p.temp.auxRound1Messages[fromPIdx] = msg
	case *AuxRound2Message:
		p.temp.auxRound2Messages[fromPIdx] = msg
	case *AuxRound3Message:
		p.temp.auxRound3Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
