package protocol

/*
OCS_struct holds all messages for the onchain-secret protocol.
*/

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

// NameOCS can be used from other packages to refer to this protocol.
const NameOCSBatch = "OCSBatch"

func init() {
	network.RegisterMessages(&ReencryptBatch{}, &ReencryptBatchReply{})
	//network.RegisterMessages()
}

// // VerifyRequest is a callback-function that can be set by a service.
// // Whenever a reencryption request is received, this function will be
// // called and its return-value used to determine whether or not to
// // allow reencryption.
type VerifyRequestBatch func(rc *ReencryptBatch) bool

// Reencrypt asks for a re-encryption share from a node
type ReencryptBatch struct {
	// U is the point from the write-request
	U []kyber.Point
	// Xc is the public key of the reader
	Xc []kyber.Point
	// VerificationData is optional and can be any slice of bytes, so that each
	// node can verify if the reencryption request is valid or not.
	VerificationData *[]byte
}

type structReencryptBatch struct {
	*onet.TreeNode
	ReencryptBatch
}

// ReencryptReply returns the share to re-encrypt from one node
type ReencryptBatchReply struct {
	Ui []*share.PubShare
	Ei []kyber.Scalar
	Fi []kyber.Scalar
}

type structReencryptBatchReply struct {
	*onet.TreeNode
	ReencryptBatchReply
}
