package auxiliary

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"mpc_tss/common"
	"mpc_tss/crypto/alice/utils"
	paillierzkproof "mpc_tss/crypto/alice/zkproof/paillier"
	"mpc_tss/crypto/facproof"
	"mpc_tss/tss"

	"github.com/golang/protobuf/proto"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round 3 already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_3 start", i)

	for j, msg := range round.temp.auxRound2Messages {
		if j == i {
			continue
		}

		r2Msg := msg.Content().(*AuxRound2Message)

		if !bytes.Equal(r2Msg.GetSsid(), round.temp.ssid) {
			common.Logger.Errorf("[j: %d] payload.ssid != round.temp.ssid")
			return round.WrapError(fmt.Errorf("[j: %d] payload.ssid != round.temp.ssid", j))
		}

		round.save.PaillierPKs[j] = r2Msg.UnmarshalPaillierPK()
		round.save.PedersenPKs[j] = r2Msg.UnmarshalPedersenPK()

		// Verify prm proof
		prmProof, err := r2Msg.UnmarshalPrmProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] unmarshal prm proof failed", j)
			return round.WrapError(fmt.Errorf("[j: %d] unmarshal prm proof failed", j))
		}
		if err := round.verifyPrmPubkeys(j, prmProof); err != nil {
			return round.WrapError(err)
		}
		contextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		if err := prmProof.Verify(contextJ); err != nil {
			common.Logger.Errorf("[j: %d] verify prm proof failed: %s", j, err.Error())
			return round.WrapError(fmt.Errorf("[j: %d] verify prm proof failed: %s", j, err.Error()))
		}

		// Verify mod proof
		modProof, err := r2Msg.UnmarshalModProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] unmarshal mod proof failed", j)
			return round.WrapError(fmt.Errorf("[j: %d] unmarshal mod proof failed", j))
		}
		if ok := modProof.Verify(contextJ, round.save.PaillierPKs[j].N); !ok {
			common.Logger.Errorf("[j: %d] mod proof verify failed", j)
			return round.WrapError(fmt.Errorf("[j: %d] mod proof verify failed", j))
		}

		common.Logger.Debugf("party: %d, round_3, calc V", i)
		hash := common.SHA512_256(
			round.temp.ssid,
			[]byte(strconv.Itoa(j)),
			r2Msg.GetSrid(),
			round.save.PaillierPKs[j].N.Bytes(),
			round.save.PedersenPKs[j].S.Bytes(),
			round.save.PedersenPKs[j].T.Bytes(),
			prmProof.Salt,
			modProof.A.Bytes(),
			modProof.B.Bytes(),
			modProof.W.Bytes(),
			r2Msg.GetRho(),
			r2Msg.GetU(),
		)

		// Verify commited V_i
		if !bytes.Equal(hash, round.temp.V[j]) {
			common.Logger.Errorf("[j: %d] hash != V", j)
			return round.WrapError(fmt.Errorf("[j: %d] commited v_i verify failed", j))
		}

		// Set rho as xor of all party's rho_i
		common.Logger.Debugf("party: %d, round_3, calc rho", i)
		round.temp.rho = utils.Xor(round.temp.rho, r2Msg.GetRho())
	}

	// P2P send fac proof
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}
		facProof, err := facproof.NewNoSmallFactorMessage(
			ProofParameter,
			round.temp.ssid,
			round.temp.rho,
			round.save.PaillierSK.P,
			round.save.PaillierSK.Q,
			round.save.PaillierPKs[i].N,
			round.save.PedersenPKs[j],
		)
		if err != nil {
			return round.WrapError(fmt.Errorf("[j: %d] calc fac proof failed: %s", j, err.Error()))
		}
		facProofBytes, err := proto.Marshal(facProof)
		if err != nil {
			return round.WrapError(fmt.Errorf("[j: %d] marshal fac proof error: %s", j, err.Error()))
		}

		common.Logger.Debugf("P[%d]: send fac proof to P[%d]", i, j)
		r3msg := NewAuxRound3Message(Pj, round.PartyID(), facProofBytes)
		round.out <- r3msg
	}
	return nil
}

func (round *round3) verifyPrmPubkeys(j int, msg *paillierzkproof.RingPederssenParameterMessage) error {
	n := new(big.Int).SetBytes(msg.N)
	s := new(big.Int).SetBytes(msg.S)
	t := new(big.Int).SetBytes(msg.T)

	if n.Cmp(round.save.PedersenPKs[j].N) != 0 {
		common.Logger.Errorf("msg.N != save.N, party: %d, msg.N = %d, save.N = %d", j, n, round.save.PedersenPKs[j].N)
		return errors.New("msg.N != save.N")
	}

	if s.Cmp(round.save.PedersenPKs[j].S) != 0 {
		common.Logger.Errorf("msg.S != save.S, party: %d", j)
		return errors.New("msg.S != save.S")
	}

	if t.Cmp(round.save.PedersenPKs[j].T) != 0 {
		common.Logger.Errorf("msg.T != save.T, party: %d", j)
		return errors.New("msg.T != save.T")
	}
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*AuxRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.auxRound3Messages {
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

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
