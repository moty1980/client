// Auto-generated to Go types and interfaces using avdl-compiler v1.4.2 (https://github.com/keybase/node-avdl-compiler)
//   Input file: avdl/keybase1/kvstore.avdl

package keybase1

import (
	"github.com/keybase/go-framed-msgpack-rpc/rpc"
	context "golang.org/x/net/context"
)

type KVEntry struct {
	TeamName   string `codec:"teamName" json:"teamName"`
	Namespace  string `codec:"namespace" json:"namespace"`
	EntryKey   string `codec:"entryKey" json:"entryKey"`
	EntryValue string `codec:"entryValue" json:"entryValue"`
	Revision   int    `codec:"revision" json:"revision"`
}

func (o KVEntry) DeepCopy() KVEntry {
	return KVEntry{
		TeamName:   o.TeamName,
		Namespace:  o.Namespace,
		EntryKey:   o.EntryKey,
		EntryValue: o.EntryValue,
		Revision:   o.Revision,
	}
}

type KVPutResult struct {
	TeamName  string `codec:"teamName" json:"teamName"`
	Namespace string `codec:"namespace" json:"namespace"`
	EntryKey  string `codec:"entryKey" json:"entryKey"`
	Revision  int    `codec:"revision" json:"revision"`
}

func (o KVPutResult) DeepCopy() KVPutResult {
	return KVPutResult{
		TeamName:  o.TeamName,
		Namespace: o.Namespace,
		EntryKey:  o.EntryKey,
		Revision:  o.Revision,
	}
}

type GetKVEntryArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	TeamName  string `codec:"teamName" json:"teamName"`
	Namespace string `codec:"namespace" json:"namespace"`
	EntryKey  string `codec:"entryKey" json:"entryKey"`
}

type PutKVEntryArg struct {
	SessionID  int    `codec:"sessionID" json:"sessionID"`
	TeamName   string `codec:"teamName" json:"teamName"`
	Namespace  string `codec:"namespace" json:"namespace"`
	EntryKey   string `codec:"entryKey" json:"entryKey"`
	EntryValue string `codec:"entryValue" json:"entryValue"`
}

type KvstoreInterface interface {
	GetKVEntry(context.Context, GetKVEntryArg) (KVEntry, error)
	PutKVEntry(context.Context, PutKVEntryArg) (KVPutResult, error)
}

func KvstoreProtocol(i KvstoreInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.kvstore",
		Methods: map[string]rpc.ServeHandlerDescription{
			"getKVEntry": {
				MakeArg: func() interface{} {
					var ret [1]GetKVEntryArg
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[1]GetKVEntryArg)
					if !ok {
						err = rpc.NewTypeError((*[1]GetKVEntryArg)(nil), args)
						return
					}
					ret, err = i.GetKVEntry(ctx, typedArgs[0])
					return
				},
			},
			"putKVEntry": {
				MakeArg: func() interface{} {
					var ret [1]PutKVEntryArg
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[1]PutKVEntryArg)
					if !ok {
						err = rpc.NewTypeError((*[1]PutKVEntryArg)(nil), args)
						return
					}
					ret, err = i.PutKVEntry(ctx, typedArgs[0])
					return
				},
			},
		},
	}
}

type KvstoreClient struct {
	Cli rpc.GenericClient
}

func (c KvstoreClient) GetKVEntry(ctx context.Context, __arg GetKVEntryArg) (res KVEntry, err error) {
	err = c.Cli.Call(ctx, "keybase.1.kvstore.getKVEntry", []interface{}{__arg}, &res)
	return
}

func (c KvstoreClient) PutKVEntry(ctx context.Context, __arg PutKVEntryArg) (res KVPutResult, err error) {
	err = c.Cli.Call(ctx, "keybase.1.kvstore.putKVEntry", []interface{}{__arg}, &res)
	return
}
