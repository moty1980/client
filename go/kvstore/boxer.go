package kvstore

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/keybase/client/go/kbcrypto"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/msgpack"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/go-crypto/ed25519"
	"golang.org/x/crypto/nacl/secretbox"
)

type KVStoreBoxer interface {
	Box(mctx libkb.MetaContext, teamID keybase1.TeamID, namespace, entryKey string, revision int, cleartextValue string) (ciphertext string, teamKeyGen keybase1.PerTeamKeyGeneration, err error)
	Unbox(mctx libkb.MetaContext, teamID keybase1.TeamID, namespace, entryKey string, revision int, ciphertext string,
		senderUID keybase1.UID, senderEldestSeqno keybase1.Seqno, senderDeviceID keybase1.DeviceID) (cleartext string, err error)
}

var _ KVStoreBoxer = (*KVStoreRealBoxer)(nil)

type KVStoreRealBoxer struct {
	libkb.Contextified
}

func NewKVStoreBoxer(g *libkb.GlobalContext) *KVStoreRealBoxer {
	return &KVStoreRealBoxer{
		Contextified: libkb.NewContextified(g),
	}
}

func (b *KVStoreRealBoxer) sign(namespace, entryKey string, clearBytes []byte, revision int, nonce [24]byte) (ret keybase1.ED25519Signature, err error) {
	// build the message
	msg, err := b.buildSignatureMsg(namespace, entryKey, clearBytes, revision, nonce)
	if err != nil {
		return ret, err
	}
	// fetch this device's signing key
	signingKey, err := b.G().ActiveDevice.SigningKey()
	if err != nil {
		return ret, err
	}
	kp, ok := signingKey.(libkb.NaclSigningKeyPair)
	if !ok || kp.Private == nil {
		return ret, libkb.KeyCannotSignError{}
	}
	// sign it
	sigInfo, err := kp.SignV2(msg, kbcrypto.SignaturePrefixTeamStore)
	if err != nil {
		return ret, err
	}
	return keybase1.ED25519Signature(sigInfo.Sig), nil
}

func (b *KVStoreRealBoxer) verify(mctx libkb.MetaContext, namespace, entryKey string, revision int,
	clearBytes []byte, sig kbcrypto.NaclSignature, nonce [24]byte,
	senderUID keybase1.UID, senderEldestSeqno keybase1.Seqno, senderDeviceID keybase1.DeviceID) (err error) {

	// build the expected message
	expectedInput, err := b.buildSignatureMsg(namespace, entryKey, clearBytes, revision, nonce)
	if err != nil {
		return err
	}
	// fetch the verify key for this user and device
	upk, err := b.G().GetUPAKLoader().LoadUPAKWithDeviceID(mctx.Ctx(), senderUID, senderDeviceID)
	if err != nil {
		return err
	}
	verifyKid, _ := upk.Current.FindSigningDeviceKID(senderDeviceID)
	// verify it
	sigInfo := kbcrypto.NaclSigInfo{
		Kid:     verifyKid.ToBinaryKID(),
		Payload: expectedInput,
		Sig:     sig,
		Prefix:  kbcrypto.SignaturePrefixTeamStore,
		Version: 2,
	}
	_, err = sigInfo.Verify()
	return err
}

func (b *KVStoreRealBoxer) buildSignatureMsg(namespace, entryKey string, clearBytes []byte, revision int, nonce [24]byte) (ret []byte, err error) {
	clearHash := sha512.Sum512(clearBytes)
	ret = append(ret, []byte(namespace)...)
	ret = append(ret, []byte(entryKey)...)
	ret = append(ret, clearHash[:]...)
	revBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(revBytes, uint32(revision))
	ret = append(ret, revBytes...)
	ret = append(ret, nonce[:]...)
	// encryptionkey
	return ret, nil
}

func newNonce() (ret [24]byte, err error) {
	randBytes, err := libkb.RandBytes(24)
	if err != nil {
		return ret, err
	}
	copy(ret[:], randBytes)
	return ret, nil
}

func (b *KVStoreRealBoxer) Box(mctx libkb.MetaContext, teamID keybase1.TeamID, namespace, entryKey string, revision int, cleartext string) (ciphertext string, teamKeyGen keybase1.PerTeamKeyGeneration, err error) {
	clearBytes := []byte(cleartext)
	nonce, err := newNonce()
	if err != nil {
		return "", keybase1.PerTeamKeyGeneration(0), err
	}
	sig, err := b.sign(namespace, entryKey, clearBytes, revision, nonce)
	if err != nil {
		return "", keybase1.PerTeamKeyGeneration(0), err
	}
	// compose sig+clearbytes
	var data []byte
	data = append(data, sig[:]...)
	data = append(data, clearBytes...)

	// fetch the encryption key
	loadArg := keybase1.FastTeamLoadArg{
		ID:            teamID,
		Applications:  []keybase1.TeamApplication{keybase1.TeamApplication_KVSTORE},
		NeedLatestKey: true,
	}
	teamLoadRes, err := mctx.G().GetFastTeamLoader().Load(mctx, loadArg)
	if len(teamLoadRes.ApplicationKeys) != 1 {
		return "", keybase1.PerTeamKeyGeneration(0), fmt.Errorf("wrong number of keys from fast-team-loading encryption key; wanted 1, got %d", len(teamLoadRes.ApplicationKeys))
	}
	appKey := teamLoadRes.ApplicationKeys[0]
	teamGen := keybase1.PerTeamKeyGeneration(appKey.Generation())

	// encrypt
	var encKey [libkb.NaclSecretBoxKeySize]byte = appKey.Key
	sealed := secretbox.Seal(nil, data, &nonce, &encKey)
	encrypted := keybase1.EncryptedKVEntry{
		V:   1,
		E:   sealed,
		N:   nonce,
		Gen: teamGen,
	}
	// pack it, string it, ship it.
	packed, err := msgpack.Encode(encrypted)
	if err != nil {
		return "", keybase1.PerTeamKeyGeneration(0), err
	}
	return base64.StdEncoding.EncodeToString(packed), teamGen, nil
}

func (b *KVStoreRealBoxer) Unbox(mctx libkb.MetaContext, teamID keybase1.TeamID, namespace, entryKey string, revision int, ciphertext string,
	senderUID keybase1.UID, senderEldestSeqno keybase1.Seqno, senderDeviceID keybase1.DeviceID) (cleartext string, err error) {

	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	var box keybase1.EncryptedKVEntry
	err = msgpack.Decode(&box, decoded)
	if err != nil {
		return "", err
	}
	// fetch the team application key for decryption
	generation := box.Gen
	loadArg := keybase1.FastTeamLoadArg{
		ID:                   teamID,
		Applications:         []keybase1.TeamApplication{keybase1.TeamApplication_KVSTORE},
		KeyGenerationsNeeded: []keybase1.PerTeamKeyGeneration{generation},
	}
	teamLoadRes, err := mctx.G().GetFastTeamLoader().Load(mctx, loadArg)

	if len(teamLoadRes.ApplicationKeys) != 1 {
		return "", fmt.Errorf("wrong number of keys from fast-team-loading decryption key; wanted 1, got %d", len(teamLoadRes.ApplicationKeys))
	}
	appKey := teamLoadRes.ApplicationKeys[0]
	// TODO: some sanity checking on this key. see chat/teams.go#147
	nonce := box.N
	if box.V != 1 {
		return "", fmt.Errorf("unsupported secret box version: %v", box.V)
	}
	decrypted, ok := secretbox.Open(
		nil, box.E, (*[24]byte)(&box.N), (*[32]byte)(&appKey.Key))
	if !ok {
		return "", libkb.NewDecryptOpenError("kvstore secretbox")
	}

	sigBytes := decrypted[0:ed25519.SignatureSize]
	var sig kbcrypto.NaclSignature
	copy(sig[:], sigBytes)
	clearBytes := decrypted[ed25519.SignatureSize:]

	err = b.verify(mctx, namespace, entryKey, revision, clearBytes, sig, nonce, senderUID, senderEldestSeqno, senderDeviceID)
	if err != nil {
		return "", err
	}
	return string(clearBytes), nil
}
