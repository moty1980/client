// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

// RPC handlers for kvstore operations

package service

import (
	"fmt"
	"strings"

	"github.com/keybase/client/go/kvstore"
	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/client/go/teams"
	"github.com/keybase/go-framed-msgpack-rpc/rpc"
	"golang.org/x/net/context"
)

type KVStoreHandler struct {
	*BaseHandler
	libkb.Contextified
	Boxer kvstore.KVStoreBoxer
}

var _ keybase1.KvstoreInterface = (*KVStoreHandler)(nil)

func NewKVStoreHandler(xp rpc.Transporter, g *libkb.GlobalContext) *KVStoreHandler {
	if g.GetKVRevisionCache() == nil {
		g.SetKVRevisionCache(kvstore.NewKVRevisionCache())
	}
	return &KVStoreHandler{
		BaseHandler:  NewBaseHandler(g, xp),
		Contextified: libkb.NewContextified(g),
		Boxer:        kvstore.NewKVStoreBoxer(g),
	}
}

func (h *KVStoreHandler) assertLoggedIn(ctx context.Context) error {
	loggedIn := h.G().ActiveDevice.Valid()
	if !loggedIn {
		return libkb.LoginRequiredError{}
	}
	return nil
}

func (h *KVStoreHandler) resolveTeam(mctx libkb.MetaContext, userInputTeamName string) (teamID keybase1.TeamID, err error) {
	if strings.Contains(userInputTeamName, ",") {
		// it's an implicit team that might not exist yet
		team, _, _, err := teams.LookupOrCreateImplicitTeam(mctx.Ctx(), mctx.G(), userInputTeamName, false /*public*/)
		return team.ID, err
	}
	return teams.GetTeamIDByNameRPC(mctx, userInputTeamName)
}

type getEntryAPIRes struct {
	Status            libkb.AppStatus               `json:"status"`
	TeamID            keybase1.TeamID               `json:"team_id"`
	Namespace         string                        `json:"namespace"`
	EntryKey          string                        `json:"entry_key"`
	TeamKeyGen        keybase1.PerTeamKeyGeneration `json:"team_key_gen"`
	Revision          int                           `json:"revision"`
	Ciphertext        string                        `json:"ciphertext"`
	CiphertextVersion int                           `json:"ciphertext_version"`
	FormatVersion     int                           `json:"format_version"`
	WriterUID         keybase1.UID                  `json:"uid"`
	WriterEldestSeqno keybase1.Seqno                `json:"eldest_seqno"`
	WriterDeviceID    keybase1.DeviceID             `json:"device_id"`
}

func (k *getEntryAPIRes) GetAppStatus() *libkb.AppStatus {
	return &k.Status
}

func (h *KVStoreHandler) serverFetch(mctx libkb.MetaContext, entryID keybase1.KVEntryID) (emptyRes getEntryAPIRes, err error) {
	var apiRes getEntryAPIRes
	apiArg := libkb.APIArg{
		Endpoint:    "team/storage",
		SessionType: libkb.APISessionTypeREQUIRED,
		Args: libkb.HTTPArgs{
			"team_id":   libkb.S{Val: entryID.TeamID.String()},
			"namespace": libkb.S{Val: entryID.Namespace},
			"entry_key": libkb.S{Val: entryID.EntryKey},
		},
	}
	err = mctx.G().API.GetDecode(mctx, apiArg, &apiRes)
	if err != nil {
		return emptyRes, err
	}
	if apiRes.TeamID != entryID.TeamID {
		return emptyRes, fmt.Errorf("api returned an unexpected teamID: %s isn't %s", apiRes.TeamID, entryID.TeamID)
	}
	if apiRes.Namespace != entryID.Namespace {
		return emptyRes, fmt.Errorf("api returned an unexpected namespace: %s isn't %s", apiRes.Namespace, entryID.Namespace)
	}
	if apiRes.EntryKey != entryID.EntryKey {
		return emptyRes, fmt.Errorf("api returned an unexpected entryKey: %s isn't %s", apiRes.EntryKey, entryID.EntryKey)
	}
	entryHash := kvstore.Hash(apiRes.Ciphertext)
	err = mctx.G().GetKVRevisionCache().Check(entryID, entryHash, apiRes.TeamKeyGen, apiRes.Revision)
	if err != nil {
		return emptyRes, err
	}
	return apiRes, nil
}

func (h *KVStoreHandler) GetKVEntry(ctx context.Context, arg keybase1.GetKVEntryArg) (res keybase1.KVEntry, err error) {
	ctx = libkb.WithLogTag(ctx, "KV")
	if err := h.assertLoggedIn(ctx); err != nil {
		return res, err
	}
	mctx := libkb.NewMetaContext(ctx, h.G())
	teamID, err := h.resolveTeam(mctx, arg.TeamName)
	if err != nil {
		return res, err
	}
	entryID := keybase1.KVEntryID{
		TeamID:    teamID,
		Namespace: arg.Namespace,
		EntryKey:  arg.EntryKey,
	}
	apiRes, err := h.serverFetch(mctx, entryID)
	if err != nil {
		return res, err
	}
	cleartext, err := h.Boxer.Unbox(mctx, entryID, apiRes.Revision, apiRes.Ciphertext, apiRes.WriterUID, apiRes.WriterEldestSeqno, apiRes.WriterDeviceID)
	if err != nil {
		return res, err
	}
	res = keybase1.KVEntry{
		TeamName:   arg.TeamName,
		Namespace:  arg.Namespace,
		EntryKey:   arg.EntryKey,
		EntryValue: cleartext,
		Revision:   apiRes.Revision,
	}
	return res, nil
}

type putEntryAPIRes struct {
	Status   libkb.AppStatus `json:"status"`
	Revision int             `json:"revision"`
}

func (k *putEntryAPIRes) GetAppStatus() *libkb.AppStatus {
	return &k.Status
}

func (h *KVStoreHandler) fetchRevisionFromCacheOrServer(mctx libkb.MetaContext, entryID keybase1.KVEntryID) (int, error) {
	prevRevision := mctx.G().GetKVRevisionCache().FetchRevision(entryID)
	if prevRevision == 0 {
		// not in the cache. check if it's in the server.
		serverRes, err := h.serverFetch(mctx, entryID)
		if err != nil {
			return 0, err
		}
		prevRevision = serverRes.Revision
	}
	return prevRevision, nil
}

func (h *KVStoreHandler) PutKVEntry(ctx context.Context, arg keybase1.PutKVEntryArg) (res keybase1.KVPutResult, err error) {
	ctx = libkb.WithLogTag(ctx, "KV")
	if err := h.assertLoggedIn(ctx); err != nil {
		return res, err
	}
	mctx := libkb.NewMetaContext(ctx, h.G())
	teamID, err := h.resolveTeam(mctx, arg.TeamName)
	if err != nil {
		return res, err
	}
	entryID := keybase1.KVEntryID{
		TeamID:    teamID,
		Namespace: arg.Namespace,
		EntryKey:  arg.EntryKey,
	}
	prevRevision, err := h.fetchRevisionFromCacheOrServer(mctx, entryID)
	if err != nil {
		return res, err
	}
	revision := prevRevision + 1
	ciphertext, teamKeyGen, err := h.Boxer.Box(mctx, entryID, revision, arg.EntryValue)
	if err != nil {
		return res, err
	}
	apiArg := libkb.APIArg{
		Endpoint:    "team/storage",
		SessionType: libkb.APISessionTypeREQUIRED,
		Args: libkb.HTTPArgs{
			"team_id":            libkb.S{Val: entryID.TeamID.String()},
			"team_key_gen":       libkb.I{Val: int(teamKeyGen)},
			"namespace":          libkb.S{Val: entryID.Namespace},
			"entry_key":          libkb.S{Val: entryID.EntryKey},
			"ciphertext":         libkb.S{Val: ciphertext},
			"ciphertext_version": libkb.I{Val: 1},
			"revision":           libkb.I{Val: revision},
		},
	}
	var apiRes putEntryAPIRes
	err = mctx.G().API.PostDecode(mctx, apiArg, &apiRes)
	if err != nil {
		return res, err
	}
	if apiRes.Revision != prevRevision+1 {
		return res, fmt.Errorf("kvstore PUT revision error. expected %d, got %d", prevRevision+1, apiRes.Revision)
	}
	entryHash := kvstore.Hash(ciphertext)
	err = mctx.G().GetKVRevisionCache().Check(entryID, entryHash, teamKeyGen, apiRes.Revision)
	if err != nil {
		return res, err
	}
	return keybase1.KVPutResult{
		TeamName:  arg.TeamName,
		Namespace: arg.Namespace,
		EntryKey:  arg.EntryKey,
		Revision:  apiRes.Revision,
	}, nil
}
