// Auto-generated by avdl-compiler v1.3.16 (https://github.com/keybase/node-avdl-compiler)
//   Input file: avdl/keybase1/saltpack.avdl

package keybase1

import (
	"github.com/keybase/go-framed-msgpack-rpc/rpc"
	context "golang.org/x/net/context"
)

type SaltpackEncryptOptions struct {
	Recipients     []string `codec:"recipients" json:"recipients"`
	HideSelf       bool     `codec:"hideSelf" json:"hideSelf"`
	NoSelfEncrypt  bool     `codec:"noSelfEncrypt" json:"noSelfEncrypt"`
	Binary         bool     `codec:"binary" json:"binary"`
	HideRecipients bool     `codec:"hideRecipients" json:"hideRecipients"`
	Signcrypt      bool     `codec:"signcrypt" json:"signcrypt"`
}

func (o SaltpackEncryptOptions) DeepCopy() SaltpackEncryptOptions {
	return SaltpackEncryptOptions{
		Recipients: (func(x []string) []string {
			var ret []string
			for _, v := range x {
				vCopy := v
				ret = append(ret, vCopy)
			}
			return ret
		})(o.Recipients),
		HideSelf:       o.HideSelf,
		NoSelfEncrypt:  o.NoSelfEncrypt,
		Binary:         o.Binary,
		HideRecipients: o.HideRecipients,
		Signcrypt:      o.Signcrypt,
	}
}

type SaltpackDecryptOptions struct {
	Interactive      bool `codec:"interactive" json:"interactive"`
	ForceRemoteCheck bool `codec:"forceRemoteCheck" json:"forceRemoteCheck"`
	UsePaperKey      bool `codec:"usePaperKey" json:"usePaperKey"`
}

func (o SaltpackDecryptOptions) DeepCopy() SaltpackDecryptOptions {
	return SaltpackDecryptOptions{
		Interactive:      o.Interactive,
		ForceRemoteCheck: o.ForceRemoteCheck,
		UsePaperKey:      o.UsePaperKey,
	}
}

type SaltpackSignOptions struct {
	Detached bool `codec:"detached" json:"detached"`
	Binary   bool `codec:"binary" json:"binary"`
}

func (o SaltpackSignOptions) DeepCopy() SaltpackSignOptions {
	return SaltpackSignOptions{
		Detached: o.Detached,
		Binary:   o.Binary,
	}
}

type SaltpackVerifyOptions struct {
	SignedBy  string `codec:"signedBy" json:"signedBy"`
	Signature []byte `codec:"signature" json:"signature"`
}

func (o SaltpackVerifyOptions) DeepCopy() SaltpackVerifyOptions {
	return SaltpackVerifyOptions{
		SignedBy:  o.SignedBy,
		Signature: append([]byte(nil), o.Signature...),
	}
}

type SaltpackEncryptedMessageInfo struct {
	Devices          []Device       `codec:"devices" json:"devices"`
	NumAnonReceivers int            `codec:"numAnonReceivers" json:"numAnonReceivers"`
	ReceiverIsAnon   bool           `codec:"receiverIsAnon" json:"receiverIsAnon"`
	Sender           SaltpackSender `codec:"sender" json:"sender"`
}

func (o SaltpackEncryptedMessageInfo) DeepCopy() SaltpackEncryptedMessageInfo {
	return SaltpackEncryptedMessageInfo{
		Devices: (func(x []Device) []Device {
			var ret []Device
			for _, v := range x {
				vCopy := v.DeepCopy()
				ret = append(ret, vCopy)
			}
			return ret
		})(o.Devices),
		NumAnonReceivers: o.NumAnonReceivers,
		ReceiverIsAnon:   o.ReceiverIsAnon,
		Sender:           o.Sender.DeepCopy(),
	}
}

type SaltpackEncryptArg struct {
	SessionID int                    `codec:"sessionID" json:"sessionID"`
	Source    Stream                 `codec:"source" json:"source"`
	Sink      Stream                 `codec:"sink" json:"sink"`
	Opts      SaltpackEncryptOptions `codec:"opts" json:"opts"`
}

func (o SaltpackEncryptArg) DeepCopy() SaltpackEncryptArg {
	return SaltpackEncryptArg{
		SessionID: o.SessionID,
		Source:    o.Source.DeepCopy(),
		Sink:      o.Sink.DeepCopy(),
		Opts:      o.Opts.DeepCopy(),
	}
}

type SaltpackDecryptArg struct {
	SessionID int                    `codec:"sessionID" json:"sessionID"`
	Source    Stream                 `codec:"source" json:"source"`
	Sink      Stream                 `codec:"sink" json:"sink"`
	Opts      SaltpackDecryptOptions `codec:"opts" json:"opts"`
}

func (o SaltpackDecryptArg) DeepCopy() SaltpackDecryptArg {
	return SaltpackDecryptArg{
		SessionID: o.SessionID,
		Source:    o.Source.DeepCopy(),
		Sink:      o.Sink.DeepCopy(),
		Opts:      o.Opts.DeepCopy(),
	}
}

type SaltpackSignArg struct {
	SessionID int                 `codec:"sessionID" json:"sessionID"`
	Source    Stream              `codec:"source" json:"source"`
	Sink      Stream              `codec:"sink" json:"sink"`
	Opts      SaltpackSignOptions `codec:"opts" json:"opts"`
}

func (o SaltpackSignArg) DeepCopy() SaltpackSignArg {
	return SaltpackSignArg{
		SessionID: o.SessionID,
		Source:    o.Source.DeepCopy(),
		Sink:      o.Sink.DeepCopy(),
		Opts:      o.Opts.DeepCopy(),
	}
}

type SaltpackVerifyArg struct {
	SessionID int                   `codec:"sessionID" json:"sessionID"`
	Source    Stream                `codec:"source" json:"source"`
	Sink      Stream                `codec:"sink" json:"sink"`
	Opts      SaltpackVerifyOptions `codec:"opts" json:"opts"`
}

func (o SaltpackVerifyArg) DeepCopy() SaltpackVerifyArg {
	return SaltpackVerifyArg{
		SessionID: o.SessionID,
		Source:    o.Source.DeepCopy(),
		Sink:      o.Sink.DeepCopy(),
		Opts:      o.Opts.DeepCopy(),
	}
}

type SaltpackInterface interface {
	SaltpackEncrypt(context.Context, SaltpackEncryptArg) error
	SaltpackDecrypt(context.Context, SaltpackDecryptArg) (SaltpackEncryptedMessageInfo, error)
	SaltpackSign(context.Context, SaltpackSignArg) error
	SaltpackVerify(context.Context, SaltpackVerifyArg) error
}

func SaltpackProtocol(i SaltpackInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.saltpack",
		Methods: map[string]rpc.ServeHandlerDescription{
			"saltpackEncrypt": {
				MakeArg: func() interface{} {
					ret := make([]SaltpackEncryptArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SaltpackEncryptArg)
					if !ok {
						err = rpc.NewTypeError((*[]SaltpackEncryptArg)(nil), args)
						return
					}
					err = i.SaltpackEncrypt(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"saltpackDecrypt": {
				MakeArg: func() interface{} {
					ret := make([]SaltpackDecryptArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SaltpackDecryptArg)
					if !ok {
						err = rpc.NewTypeError((*[]SaltpackDecryptArg)(nil), args)
						return
					}
					ret, err = i.SaltpackDecrypt(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"saltpackSign": {
				MakeArg: func() interface{} {
					ret := make([]SaltpackSignArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SaltpackSignArg)
					if !ok {
						err = rpc.NewTypeError((*[]SaltpackSignArg)(nil), args)
						return
					}
					err = i.SaltpackSign(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"saltpackVerify": {
				MakeArg: func() interface{} {
					ret := make([]SaltpackVerifyArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SaltpackVerifyArg)
					if !ok {
						err = rpc.NewTypeError((*[]SaltpackVerifyArg)(nil), args)
						return
					}
					err = i.SaltpackVerify(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type SaltpackClient struct {
	Cli rpc.GenericClient
}

func (c SaltpackClient) SaltpackEncrypt(ctx context.Context, __arg SaltpackEncryptArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.saltpack.saltpackEncrypt", []interface{}{__arg}, nil)
	return
}

func (c SaltpackClient) SaltpackDecrypt(ctx context.Context, __arg SaltpackDecryptArg) (res SaltpackEncryptedMessageInfo, err error) {
	err = c.Cli.Call(ctx, "keybase.1.saltpack.saltpackDecrypt", []interface{}{__arg}, &res)
	return
}

func (c SaltpackClient) SaltpackSign(ctx context.Context, __arg SaltpackSignArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.saltpack.saltpackSign", []interface{}{__arg}, nil)
	return
}

func (c SaltpackClient) SaltpackVerify(ctx context.Context, __arg SaltpackVerifyArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.saltpack.saltpackVerify", []interface{}{__arg}, nil)
	return
}
