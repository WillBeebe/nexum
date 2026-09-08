package message

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/hpke"
)

// Seal encrypts on the sender. Its fresh key must be durably stored locally
// before publishing the offer; it must not accompany the ciphertext to Nex.
func Seal(i Identity, recipient Public, text []byte, invitation string, now, expiry time.Time) (Offer, []byte, error) {
	return SealWithOptions(i, recipient, text, invitation, now, expiry, SendOptions{})
}

func SealWithOptions(i Identity, recipient Public, text []byte, invitation string, now, expiry time.Time, options SendOptions) (Offer, []byte, error) {
	p, err := i.Public()
	if err != nil {
		return Offer{}, nil, err
	}
	if len(text) > MaxText || !utf8.Valid(text) || recipient.Validate() != nil {
		return Offer{}, nil, ErrInvalid
	}
	id, key := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return Offer{}, nil, err
	}
	if _, err := rand.Read(key); err != nil {
		return Offer{}, nil, err
	}
	o := Offer{Terms: Terms{Kind: Kind, ID: hex.EncodeToString(id), Sender: p, Recipient: recipient,
		Invitation: invitation, CreatedAt: now.UTC(), ExpiresAt: expiry.UTC(), KeySuite: HPKESuite, ConversationID: options.ConversationID, ReplyTo: options.ReplyTo, Trade: options.Trade}}
	if options.KeySuite != "" {
		o.Terms.KeySuite = options.KeySuite
	}
	if o.Terms.ConversationID == "" {
		o.Terms.ConversationID = o.Terms.ID
	}
	o.Ciphertext, err = encrypt(key, text, wire("text", o.Terms))
	if err != nil {
		return Offer{}, nil, err
	}
	o.Signature = sign(i, "offer", o.unsigned())
	return o, key, o.Verify()
}

// WrapKey releases a content key only against the intended recipient's signed
// acceptance. X25519 + HKDF-SHA256 derives an AES-256-GCM wrapping key, bound to
// both identities, the exact envelope and its acceptance. The relay sees only
// the ephemeral public key and encrypted content key.
func WrapKey(i Identity, o Offer, d Decision, contentKey []byte) (Release, error) {
	p, err := i.Public()
	if err != nil {
		return Release{}, err
	}
	if p.ID() != o.Terms.Sender.ID() {
		return Release{}, ErrParty
	}
	if d.Verify(o) != nil || d.Action != "agree" || len(contentKey) != 32 {
		return Release{}, ErrInvalid
	}
	// Refuse a damaged/mismatched local outbox key before releasing it.
	if _, err := decrypt(contentKey, o.Ciphertext, wire("text", o.Terms)); err != nil {
		return Release{}, err
	}
	if o.Terms.KeySuite == RekeySuite {
		return wrapRekey(i, o, d, contentKey)
	}
	if o.Terms.KeySuite == HPKESuite {
		public, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(o.Terms.Recipient.Encryption)
		if err != nil {
			return Release{}, err
		}
		sender, err := messageHPKE().NewSender(public, hpkeInfo(o, d))
		if err != nil {
			return Release{}, err
		}
		enc, sealer, err := sender.Setup(rand.Reader)
		if err != nil {
			return Release{}, err
		}
		r := Release{EnvelopeHash: o.Hash(), AcceptanceHash: d.Hash(), Ephemeral: enc}
		r.WrappedKey, err = sealer.Seal(contentKey, r.context())
		if err != nil {
			return Release{}, err
		}
		r.Signature = sign(i, "release", r.unsigned())
		return r, r.Verify(o, d)
	}
	// Read compatibility for already-signed v1 offers only.
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Release{}, err
	}
	r := Release{EnvelopeHash: o.Hash(), AcceptanceHash: d.Hash(), Ephemeral: ephemeral.PublicKey().Bytes()}
	wrappingKey, err := derive(ephemeral, o.Terms.Recipient.Encryption, r.context())
	if err != nil {
		return Release{}, err
	}
	r.WrappedKey, err = encrypt(wrappingKey, contentKey, r.context())
	if err != nil {
		return Release{}, err
	}
	r.Signature = sign(i, "release", r.unsigned())
	return r, r.Verify(o, d)
}

func Open(i Identity, r Record) ([]byte, error) {
	if err := r.Verify(); err != nil {
		return nil, err
	}
	p, err := i.Public()
	if err != nil {
		return nil, err
	}
	if p.ID() != r.Offer.Terms.Recipient.ID() {
		return nil, ErrParty
	}
	if r.Release == nil {
		return nil, ErrNotReady
	}
	// Long-lived identity keys cannot open the one-time-key suite.
	if r.Offer.Terms.KeySuite == RekeySuite {
		return nil, ErrNotReady
	}
	if r.Offer.Terms.KeySuite == HPKESuite {
		private, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(i.Encryption)
		if err != nil {
			return nil, err
		}
		receiver, err := messageHPKE().NewReceiver(private, hpkeInfo(r.Offer, *r.Decision))
		if err != nil {
			return nil, err
		}
		opener, err := receiver.Setup(r.Release.Ephemeral)
		if err != nil {
			return nil, err
		}
		key, err := opener.Open(r.Release.WrappedKey, r.Release.context())
		if err != nil {
			return nil, err
		}
		return decrypt(key, r.Offer.Ciphertext, wire("text", r.Offer.Terms))
	}
	private, err := ecdh.X25519().NewPrivateKey(i.Encryption)
	if err != nil {
		return nil, err
	}
	key, err := derive(private, r.Release.Ephemeral, r.Release.context())
	if err != nil {
		return nil, err
	}
	contentKey, err := decrypt(key, r.Release.WrappedKey, r.Release.context())
	if err != nil {
		return nil, err
	}
	return decrypt(contentKey, r.Offer.Ciphertext, wire("text", r.Offer.Terms))
}

func (r Release) context() []byte {
	r.Signature, r.WrappedKey = nil, nil
	return wire("key-wrap", r)
}
func derive(private *ecdh.PrivateKey, public, context []byte) ([]byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	secret, err := private.ECDH(peer)
	if err != nil {
		return nil, err
	}
	salt := sha256.Sum256(context)
	return hkdf.Key(sha256.New, secret, salt[:], "nex/message/v1/content-key", 32)
}
func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func encrypt(key, text, aad []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, text, aad), nil
}
func decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrInvalid
	}
	return gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], aad)
}

func messageHPKE() hpke.Suite {
	return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
}
func hpkeInfo(o Offer, d Decision) []byte {
	return wire("hpke", []string{HPKESuite, o.Hash(), d.Hash()})
}
