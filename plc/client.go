package plc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/identity"
)

type Client struct {
	h           *http.Client
	service     string
	pdsHostname string
	rotationKey *atcrypto.PrivateKeyK256
}

type ClientArgs struct {
	H           *http.Client
	Service     string
	RotationKey []byte
	PdsHostname string
}

func NewClient(args *ClientArgs) (*Client, error) {
	if args.Service == "" {
		args.Service = "https://plc.directory"
	}

	if args.H == nil {
		args.H = util.RobustHTTPClient()
	}

	rk, err := atcrypto.ParsePrivateBytesK256([]byte(args.RotationKey))
	if err != nil {
		return nil, err
	}

	return &Client{
		h:           args.H,
		service:     args.Service,
		rotationKey: rk,
		pdsHostname: args.PdsHostname,
	}, nil
}

func (c *Client) CreateDID(sigkey *atcrypto.PrivateKeyK256, recovery string, handle string) (string, *Operation, error) {
	pubsigkey, err := sigkey.PublicKey()
	if err != nil {
		return "", nil, err
	}

	pubrotkey, err := c.rotationKey.PublicKey()
	if err != nil {
		return "", nil, err
	}

	// todo
	rotationKeys := []string{pubrotkey.DIDKey()}
	if recovery != "" {
		rotationKeys = func(recovery string) []string {
			newRotationKeys := []string{recovery}
			for _, k := range rotationKeys {
				newRotationKeys = append(newRotationKeys, k)
			}
			return newRotationKeys
		}(recovery)
	}

	op := Operation{
		Type: "plc_operation",
		VerificationMethods: map[string]string{
			"atproto": pubsigkey.DIDKey(),
		},
		RotationKeys: rotationKeys,
		AlsoKnownAs: []string{
			"at://" + handle,
		},
		Services: map[string]identity.OperationService{
			"atproto_pds": {
				Type:     "AtprotoPersonalDataServer",
				Endpoint: "https://" + c.pdsHostname,
			},
		},
		Prev: nil,
	}

	if err := c.SignOp(sigkey, &op); err != nil {
		return "", nil, err
	}

	did, err := DidFromOp(&op)
	if err != nil {
		return "", nil, err
	}

	return did, &op, nil
}

func (c *Client) SignOp(sigkey *atcrypto.PrivateKeyK256, op *Operation) error {
	b, err := op.MarshalCBOR()
	if err != nil {
		return err
	}

	sig, err := c.rotationKey.HashAndSign(b)
	if err != nil {
		return err
	}

	op.Sig = base64.RawURLEncoding.EncodeToString(sig)

	return nil
}

func (c *Client) SendOperation(ctx context.Context, did string, op *Operation) error {
	b, err := json.Marshal(op)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.service+"/"+url.QueryEscape(did), bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", "application/json")

	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error sending operation. status code: %d, response: %s", resp.StatusCode, string(b))
	}

	return nil
}

func DidFromOp(op *Operation) (string, error) {
	b, err := op.MarshalCBOR()
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	b32 := strings.ToLower(base32.StdEncoding.EncodeToString(s[:]))
	return "did:plc:" + b32[0:24], nil
}
