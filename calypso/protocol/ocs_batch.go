package protocol

/*
The onchain-protocol implements the key-reencryption described in Lefteris'
paper-draft about onchain-secrets (called BlockMage).
*/

import (
	"crypto/sha256"
	"sync"
	"time"

	"go.dedis.ch/cothority/v3"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	onet.GlobalProtocolRegister(NameOCSBatch, NewOCSBatch)
}

// OCS is only used to re-encrypt a public point. Before calling `Start`,
// DKG and U must be initialized by the caller.
type OCSBatch struct {
	*onet.TreeNodeInstance
	Shared    *dkgprotocol.SharedSecret // Shared represents the private key
	Poly      *share.PubPoly            // Represents all public keys
	U         []kyber.Point             // U is the encrypted secret
	Xc        []kyber.Point             // The client's public key
	Threshold int                       // How many replies are needed to re-create the secret
	// VerificationData is given to the VerifyRequest and has to hold everything
	// needed to verify the request is valid.
	VerificationData []byte
	Failures         int // How many failures occured so far
	// Can be set by the service to decide whether or not to
	// do the reencryption
	Verify VerifyRequestBatch
	// Reencrypted receives a 'true'-value when the protocol finished successfully,
	// or 'false' if not enough shares have been collected.
	Reencrypted chan bool
	Uis         [][]*share.PubShare // re-encrypted shares
	// private fields
	replies  []ReencryptBatchReply
	timeout  *time.Timer
	doneOnce sync.Once
	wgBatch  sync.WaitGroup
}

type job struct {
	index int
	// replies []ReencryptBatchReply
}

var wgBatchReply sync.WaitGroup

// NewOCS initialises the structure for use in one round
func NewOCSBatch(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	o := &OCSBatch{
		TreeNodeInstance: n,
		Reencrypted:      make(chan bool, 1),
		Threshold:        len(n.Roster().List) - (len(n.Roster().List)-1)/3,
	}

	err := o.RegisterHandlers(o.reencryptBatch, o.reencryptBatchReply)
	if err != nil {
		return nil, xerrors.Errorf("registring handlers: %v", err)
	}
	return o, nil
}

// Start asks all children to reply with a shared reencryption
func (o *OCSBatch) Start() error {
	log.Lvl3("Starting Protocol")
	if o.Shared == nil {
		o.finish(false)
		return xerrors.New("please initialize Shared first")
	}
	if o.U == nil {
		o.finish(false)
		return xerrors.New("please initialize U first")
	}
	rc := &ReencryptBatch{
		U:  o.U,
		Xc: o.Xc,
	}
	if len(o.VerificationData) > 0 {
		rc.VerificationData = &o.VerificationData
	}
	// if o.Verify != nil {
	// 	if !o.Verify(rc) {
	// 		o.finish(false)
	// 		return xerrors.New("refused to reencrypt")
	// 	}
	// }
	o.timeout = time.AfterFunc(50*time.Minute, func() {
		log.Lvl1("OCS protocol timeout")
		o.finish(false)
	})
	errs := o.Broadcast(rc)
	if len(errs) > (len(o.Roster().List)-1)/3 {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func workerBatch(jobChan <-chan job, ui []*share.PubShare, ei []kyber.Scalar, fi []kyber.Scalar, o *OCSBatch, r *structReencryptBatch) {
	defer o.wgBatch.Done()
	for j := range jobChan {
		processBatch(j, ui, ei, fi, o, r)
	}
}

func processBatch(j job, ui []*share.PubShare, ei []kyber.Scalar, fi []kyber.Scalar, o *OCSBatch, r *structReencryptBatch) {
	i := j.index
	ui[i] = o.getUI(r.U[i], r.Xc[i])

	// if o.Verify != nil {
	// 	if !o.Verify(&r.ReencryptBatch) {
	// 		log.Lvl2(o.ServerIdentity(), "refused to reencrypt")
	// 		return cothority.ErrorOrNil(o.SendToParent(&ReencryptBatchReply{}),
	// 			"sending ReencryptReply to parent")
	// 	}
	// }

	// Calculating proofs
	si := cothority.Suite.Scalar().Pick(o.Suite().RandomStream())
	uiHat := cothority.Suite.Point().Mul(si, cothority.Suite.Point().Add(r.U[i], r.Xc[i]))
	hiHat := cothority.Suite.Point().Mul(si, nil)
	hash := sha256.New()
	ui[i].V.MarshalTo(hash)
	uiHat.MarshalTo(hash)
	hiHat.MarshalTo(hash)
	ei[i] = cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
	fi[i] = cothority.Suite.Scalar().Add(si, cothority.Suite.Scalar().Mul(ei[i], o.Shared.V))
}

// Reencrypt is received by every node to give his part of
// the share
func (o *OCSBatch) reencryptBatch(r structReencryptBatch) error {
	log.Lvl1(o.Name() + ": starting reencrypt")
	defer o.Done()

	num := len(r.U)
	ui := make([]*share.PubShare, num)
	ei := make([]kyber.Scalar, num)
	fi := make([]kyber.Scalar, num)

	for i := 0; i < num; i++ {
		ui[i] = o.getUI(r.U[i], r.Xc[i])

		// if o.Verify != nil {
		// 	if !o.Verify(&r.ReencryptBatch) {
		// 		log.Lvl2(o.ServerIdentity(), "refused to reencrypt")
		// 		return cothority.ErrorOrNil(o.SendToParent(&ReencryptBatchReply{}),
		// 			"sending ReencryptReply to parent")
		// 	}
		// }

		// Calculating proofs
		si := cothority.Suite.Scalar().Pick(o.Suite().RandomStream())
		uiHat := cothority.Suite.Point().Mul(si, cothority.Suite.Point().Add(r.U[i], r.Xc[i]))
		hiHat := cothority.Suite.Point().Mul(si, nil)
		hash := sha256.New()
		ui[i].V.MarshalTo(hash)
		uiHat.MarshalTo(hash)
		hiHat.MarshalTo(hash)
		ei[i] = cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
		fi[i] = cothority.Suite.Scalar().Add(si, cothority.Suite.Scalar().Mul(ei[i], o.Shared.V))
	}

	// jobChan := make(chan job, num)

	// for i := 0; i < num; i++ {
	// 	jobChan <- job{index: i}
	// }
	// close(jobChan)

	// //workers
	// for i := 0; i < 8; i++ {
	// 	o.wgBatch.Add(1)
	// 	go workerBatch(jobChan, ui, ei, fi, o, &r)
	// }
	// o.wgBatch.Wait()

	return cothority.ErrorOrNil(
		o.SendToParent(&ReencryptBatchReply{
			Ui: ui,
			Ei: ei,
			Fi: fi,
		}),
		"sending ReencryptReply to parent",
	)
}

func workerBatchReply(jobChan <-chan job, o *OCSBatch) {
	defer wgBatchReply.Done()
	for j := range jobChan {
		processBatchReply(j, o)
	}
}

func processBatchReply(j job, o *OCSBatch) {
	i := j.index
	log.Lvl1("working on transaction", i)
	o.Uis[i] = make([]*share.PubShare, len(o.List()))
	o.Uis[i][0] = o.getUI(o.U[i], o.Xc[i])

	for _, r := range o.replies {

		// Verify proofs
		ufi := cothority.Suite.Point().Mul(r.Fi[i], cothority.Suite.Point().Add(o.U[i], o.Xc[i]))
		uiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(r.Ei[i]), r.Ui[i].V)
		uiHat := cothority.Suite.Point().Add(ufi, uiei)

		gfi := cothority.Suite.Point().Mul(r.Fi[i], nil)
		gxi := o.Poly.Eval(r.Ui[i].I).V
		hiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(r.Ei[i]), gxi)
		hiHat := cothority.Suite.Point().Add(gfi, hiei)
		hash := sha256.New()
		r.Ui[i].V.MarshalTo(hash)
		uiHat.MarshalTo(hash)
		hiHat.MarshalTo(hash)
		e := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
		if e.Equal(r.Ei[i]) {
			o.Uis[i][r.Ui[i].I] = r.Ui[i]
		} else {
			log.Lvl1("Received invalid share from node", r.Ui[i].I)
		}
	}
}

// reencryptReply is the root-node waiting for all replies and generating
// the reencryption key.
func (o *OCSBatch) reencryptBatchReply(rr structReencryptBatchReply) error {
	if rr.ReencryptBatchReply.Ui == nil {
		log.Lvl2("Node", rr.ServerIdentity, "refused to reply")
		o.Failures++
		if o.Failures > len(o.Roster().List)-o.Threshold {
			log.Lvl2(rr.ServerIdentity, "couldn't get enough shares")
			o.finish(false)
		}
		return nil
	}
	o.replies = append(o.replies, rr.ReencryptBatchReply)

	//log.Lvl1(len(o.replies))

	if len(o.replies) < int(o.Threshold-1) {
		return nil
	}

	log.Lvl1("begin to process the shares.")

	num := len(o.replies[0].Fi)

	jobChan := make(chan job, num)

	for i := 0; i < num; i++ {
		jobChan <- job{index: i}
	}
	close(jobChan)

	//workers
	for i := 0; i < 128; i++ {
		wgBatchReply.Add(1)
		go workerBatchReply(jobChan, o)
	}

	wgBatchReply.Wait()
	o.finish(true)

	// If we are leaving by here it means that we do not have
	// enough replies yet. We must eventually trigger a finish()
	// somehow. It will either happen because we get another
	// reply, and now we have enough, or because we get enough
	// failures and know to give up, or because o.timeout triggers
	// and calls finish(false) in it's callback function.

	return nil
}

func (o *OCSBatch) getUI(U, Xc kyber.Point) *share.PubShare {
	v := cothority.Suite.Point().Mul(o.Shared.V, U)
	v.Add(v, cothority.Suite.Point().Mul(o.Shared.V, Xc))
	return &share.PubShare{
		I: o.Shared.Index,
		V: v,
	}
}

func (o *OCSBatch) finish(result bool) {
	o.timeout.Stop()
	select {
	case o.Reencrypted <- result:
		// suceeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	o.doneOnce.Do(func() { o.Done() })
}
