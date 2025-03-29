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

	"github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/bluesky-social/indigo/util"
)

type Client struct {
	h           *http.Client
	service     string
	pdsHostname string
	rotationKey *crypto.PrivateKeyK256
}

type ClientArgs struct {
	Service     string
	RotationKey []byte
	PdsHostname string
}

func NewClient(args *ClientArgs) (*Client, error) {
	if args.Service == "" {
		args.Service = "https://plc.directory"
	}

	rk, err := crypto.ParsePrivateBytesK256([]byte(args.RotationKey))
	if err != nil {
		return nil, err
	}

	return &Client{
		h:           util.RobustHTTPClient(),
		service:     args.Service,
		rotationKey: rk,
		pdsHostname: args.PdsHostname,
	}, nil
}

func (c *Client) CreateDID(ctx context.Context, sigkey *crypto.PrivateKeyK256, recovery string, handle string) (string, *PlcOperation, error) {
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

	op := PlcOperation{
		Type: "plc_operation",
		VerificationMethods: map[string]string{
			"atproto": pubsigkey.DIDKey(),
		},
		RotationKeys: rotationKeys,
		AlsoKnownAs: []string{
			"at://" + handle,
		},
		Services: map[string]PlcOperationService{
			"atproto_pds": {
				Type:     "AtprotoPersonalDataServer",
				Endpoint: "https://" + c.pdsHostname,
			},
		},
		Prev: nil,
	}

	signed, err := c.FormatAndSignAtprotoOp(sigkey, op)
	if err != nil {
		return "", nil, err
	}

	did, err := didFromOp(signed)
	if err != nil {
		return "", nil, err
	}

	return did, &op, nil
}

func didFromOp(op *PlcOperation) (string, error) {
	b, err := op.MarshalCBOR()
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	b32 := strings.ToLower(base32.StdEncoding.EncodeToString(s[:]))
	return "did:plc:" + b32[0:24], nil
}

func (c *Client) FormatAndSignAtprotoOp(sigkey *crypto.PrivateKeyK256, op PlcOperation) (*PlcOperation, error) {
	b, err := op.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	sig, err := c.rotationKey.HashAndSign(b)
	if err != nil {
		return nil, err
	}

	op.Sig = base64.RawURLEncoding.EncodeToString(sig)

	return &op, nil
}

func (c *Client) SendOperation(ctx context.Context, did string, op *PlcOperation) error {
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
