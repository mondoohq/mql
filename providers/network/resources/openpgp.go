// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (p *mqlOpenpgpEntities) list(content string) ([]any, error) {
	entries, err := readKeyRing(content)
	if err != nil {
		return nil, err
	}

	res := []any{}
	// to create certificate resources
	for i := range entries {
		entity := entries[i]

		if entity == nil {
			continue
		}

		pubKey, err := newMqlOpenpgpPublicKey(p.MqlRuntime, entity.PrimaryKey)
		if err != nil {
			return nil, err
		}

		mqlCert, err := CreateResource(p.MqlRuntime, "openpgp.entity", map[string]*llx.RawData{
			"primaryPublicKey": llx.ResourceData(pubKey, "openpgp.publicKey"),
		})
		if err != nil {
			return nil, err
		}

		c := mqlCert.(*mqlOpenpgpEntity)
		c._identities = entity.Identities
		res = append(res, c)
	}
	return res, nil
}

const armorBegin = "-----BEGIN PGP "

// readKeyRing reads every key of an OpenPGP keyring. Armored content can hold
// several key blocks one after another (vendor release key files often carry
// two keys), and each one is read. Blocks other than keys, such as a detached
// signature, are skipped. Content without armor is read as a binary keyring,
// the format gpg --export and gpg --dearmor write.
func readKeyRing(content string) (openpgp.EntityList, error) {
	if !strings.Contains(content, armorBegin) {
		// Every binary OpenPGP packet starts with a tag byte whose high bit
		// is set; anything else is neither armored nor binary key data.
		if content == "" || content[0]&0x80 == 0 {
			return nil, errors.New("no armored or binary OpenPGP key data found")
		}
		return openpgp.ReadKeyRing(strings.NewReader(content))
	}

	var res openpgp.EntityList
	var skipped []string
	rest := content
	for {
		start := strings.Index(rest, armorBegin)
		if start < 0 {
			break
		}
		// armor.Decode buffers its reader, so each block is decoded from
		// its own slice of the content.
		segment := rest[start:]
		rest = ""
		if next := strings.Index(segment[len(armorBegin):], armorBegin); next >= 0 {
			rest = segment[len(armorBegin)+next:]
			segment = segment[:len(armorBegin)+next]
		}

		block, err := armor.Decode(strings.NewReader(segment))
		if err == io.EOF {
			// the marker text without a complete armor header line
			continue
		}
		if err != nil {
			return nil, err
		}
		if block.Type != openpgp.PublicKeyType && block.Type != openpgp.PrivateKeyType {
			skipped = append(skipped, block.Type)
			continue
		}
		entities, err := openpgp.ReadKeyRing(block.Body)
		if err != nil {
			return nil, err
		}
		res = append(res, entities...)
	}

	if len(res) == 0 {
		if len(skipped) > 0 {
			return nil, errors.New("expected public or private key block, got: " + strings.Join(skipped, ", "))
		}
		return nil, errors.New("no armored OpenPGP data found")
	}
	return res, nil
}

func pgpAlgoString(algorithm packet.PublicKeyAlgorithm) string {
	var pubKeyAlgo string

	switch algorithm {
	case packet.PubKeyAlgoRSA:
		pubKeyAlgo = "rsa"
	case packet.PubKeyAlgoRSAEncryptOnly:
		pubKeyAlgo = "rsa_encrypt_only"
	case packet.PubKeyAlgoRSASignOnly:
		pubKeyAlgo = "rsa_sign_only"
	case packet.PubKeyAlgoElGamal:
		pubKeyAlgo = "elgamal"
	case packet.PubKeyAlgoDSA:
		pubKeyAlgo = "dsa"
	case packet.PubKeyAlgoECDH:
		pubKeyAlgo = "ecdh"
	case packet.PubKeyAlgoECDSA:
		pubKeyAlgo = "ecdsa"
	case packet.PubKeyAlgoEdDSA:
		pubKeyAlgo = "eddsa"
	}

	return pubKeyAlgo
}

func newMqlOpenpgpPublicKey(runtime *plugin.Runtime, publicKey *packet.PublicKey) (*mqlOpenpgpPublicKey, error) {
	pubKeyAlgo := pgpAlgoString(publicKey.PubKeyAlgo)
	// we ignore the error here since it happens only when no algorithm is found
	bitlength, _ := publicKey.BitLength()

	o, err := CreateResource(runtime, "openpgp.publicKey", map[string]*llx.RawData{
		"id":           llx.StringData(publicKey.KeyIdString()),
		"version":      llx.IntData(int64(publicKey.Version)),
		"fingerprint":  llx.StringData(hex.EncodeToString(publicKey.Fingerprint)),
		"keyAlgorithm": llx.StringData(pubKeyAlgo),
		"bitLength":    llx.IntData(int64(bitlength)),
		"creationTime": llx.TimeData(publicKey.CreationTime),
	})
	if err != nil {
		return nil, err
	}

	return o.(*mqlOpenpgpPublicKey), nil
}

type mqlOpenpgpEntityInternal struct {
	_identities map[string]*openpgp.Identity
}

func (r *mqlOpenpgpEntity) id() (string, error) {
	fp := r.PrimaryPublicKey.Data.GetFingerprint()
	if fp.Error != nil {
		return "", fp.Error
	}
	return "openpgp.entity/" + fp.Data, nil
}

func (r *mqlOpenpgpEntity) identities() ([]any, error) {
	fp := r.PrimaryPublicKey.Data.GetFingerprint()
	if fp.Error != nil {
		return nil, fp.Error
	}

	res := []any{}
	for k := range r._identities {
		identity := r._identities[k]
		o, err := CreateResource(r.MqlRuntime, "openpgp.identity", map[string]*llx.RawData{
			"fingerprint": llx.StringData(fp.Data),
			"id":          llx.StringData(identity.UserId.Id),
			"name":        llx.StringData(identity.UserId.Name),
			"email":       llx.StringData(identity.UserId.Email),
			"comment":     llx.StringData(identity.UserId.Comment),
		})
		if err != nil {
			return nil, err
		}
		cur := o.(*mqlOpenpgpIdentity)
		cur._signatures = identity.Signatures

		res = append(res, cur)
	}

	return res, nil
}

func (r *mqlOpenpgpPublicKey) id() (string, error) {
	return "openpgp.publickey/" + r.Fingerprint.Data, nil
}

type mqlOpenpgpIdentityInternal struct {
	_signatures []*packet.Signature
}

func (r *mqlOpenpgpIdentity) id() (string, error) {
	// Use the full UserId (name + comment + email), not just the name: a key can
	// carry several user IDs that share a name but differ by email/comment, and
	// keying on Name alone collides so the resource cache drops all but the first.
	return "openpgp.identity/" + r.Fingerprint.Data + "/" + r.Id.Data, nil
}

func (r *mqlOpenpgpIdentity) signatures() ([]any, error) {
	res := []any{}
	for k := range r._signatures {
		signature := r._signatures[k]

		var signatureType string
		switch signature.SigType {
		case packet.SigTypeBinary:
			signatureType = "binary"
		case packet.SigTypeText:
			signatureType = "text"
		case packet.SigTypeGenericCert:
			signatureType = "generic_cert"
		case packet.SigTypePersonaCert:
			signatureType = "persona_cert"
		case packet.SigTypeCasualCert:
			signatureType = "casual_cert"
		case packet.SigTypePositiveCert:
			signatureType = "positive_cert"
		case packet.SigTypeSubkeyBinding:
			signatureType = "subkey_binding"
		case packet.SigTypePrimaryKeyBinding:
			signatureType = "primary_key_binding"
		case packet.SigTypeDirectSignature:
			signatureType = "direct_signature"
		case packet.SigTypeKeyRevocation:
			signatureType = "key_revocation"
		case packet.SigTypeSubkeyRevocation:
			signatureType = "subkey_revocation"
		case packet.SigTypeCertificationRevocation:
			signatureType = "cert_revocation"
		}

		lifetime := int64(-1)
		var expirationTime *llx.RawData
		if signature.SigLifetimeSecs != nil {
			// NOTE: this can potentially overflow
			lifetime = int64(*signature.SigLifetimeSecs)

			expiry := signature.CreationTime.Add(time.Duration(*signature.SigLifetimeSecs) * time.Second)
			diff := expiry.Unix() - time.Now().Unix()
			ts := llx.DurationToTime(diff)
			expirationTime = llx.TimeData(ts)
		} else {
			expirationTime = llx.NilData
		}

		keyLifetime := int64(-1)
		var keyExpirationTime *llx.RawData
		if signature.KeyLifetimeSecs != nil {
			// NOTE: this can potentially overflow
			keyLifetime = int64(*signature.KeyLifetimeSecs)

			expiry := signature.CreationTime.Add(time.Duration(*signature.KeyLifetimeSecs) * time.Second)
			diff := expiry.Unix() - time.Now().Unix()
			ts := llx.DurationToTime(diff)
			keyExpirationTime = llx.TimeData(ts)
		} else {
			keyExpirationTime = llx.NilData
		}

		o, err := CreateResource(r.MqlRuntime, "openpgp.signature", map[string]*llx.RawData{
			"fingerprint":     llx.StringData(r.Fingerprint.Data),
			"identityName":    llx.StringData(r.Id.Data),
			"hash":            llx.StringData(signature.Hash.String()),
			"version":         llx.IntData(int64(signature.Version)),
			"signatureType":   llx.StringData(signatureType),
			"keyAlgorithm":    llx.StringData(pgpAlgoString(signature.PubKeyAlgo)),
			"creationTime":    llx.TimeData(signature.CreationTime),
			"lifetimeSecs":    llx.IntData(lifetime),
			"expiresIn":       expirationTime,
			"keyLifetimeSecs": llx.IntData(keyLifetime),
			"keyExpiresIn":    keyExpirationTime,
		})
		if err != nil {
			return nil, err
		}
		sig := o.(*mqlOpenpgpSignature)
		res = append(res, sig)
	}

	return res, nil
}

func (r *mqlOpenpgpSignature) id() (string, error) {
	// An identity carries several signatures (self-cert, revocation, third-party
	// certifications) that commonly share the same hash algorithm, so the hash
	// alone does not disambiguate them. Add the signature type and creation time
	// so distinct signatures don't collide and get dropped by the resource cache.
	created := ""
	if r.CreationTime.Data != nil {
		created = strconv.FormatInt(r.CreationTime.Data.Unix(), 10)
	}
	return "openpgp.signature/" + r.Fingerprint.Data + "/" + r.IdentityName.Data +
		"/" + r.Hash.Data + "/" + r.SignatureType.Data + "/" + created, nil
}
