package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type CmdExport struct {
	Algorithm string `required:"" help:"Intended algorithm to use with the exported keys (e.g. RS256). Must be provided explicitly to avoid 'algorithm confusion' attacks."`
}

func (e *CmdExport) Run(ktx *Context) error {
	s := jwk.NewSet()
	for _, keySuffix := range []string{keySuffixCurrent, keySuffixNext, keySuffixPrevious} {
		keyID := ktx.keyAlias(keySuffix)

		kmsKeyDescription, err := ktx.kms.DescribeKey(context.Background(), &kms.DescribeKeyInput{
			KeyId: keyID,
		})
		if err != nil {
			return fmt.Errorf("describing key %s: %w", *keyID, err)
		}

		awsPubKey, err := ktx.kms.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{
			KeyId: keyID,
		})
		if err != nil {
			return fmt.Errorf("getting public key for %s: %w", *keyID, err)
		}

		pk, err := x509.ParsePKIXPublicKey(awsPubKey.PublicKey)
		if err != nil {
			return fmt.Errorf("decoding public key for %s: %w", *keyID, err)
		}

		key, err := jwk.PublicKeyOf(pk)
		if err != nil {
			return fmt.Errorf("converting public key for %s: %w", *keyID, err)
		}

		if err := key.Set(jwk.KeyIDKey, *kmsKeyDescription.KeyMetadata.KeyId); err != nil {
			return fmt.Errorf("setting key ID for %s: %w", *keyID, err)
		}

		if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return fmt.Errorf("setting key usage for %s: %w", *keyID, err)
		}

		if err := key.Set(jwk.AlgorithmKey, jwa.KeyAlgorithmFrom(e.Algorithm)); err != nil {
			return fmt.Errorf("setting key usage for %s: %w", *keyID, err)
		}

		if err := s.AddKey(key); err != nil {
			return fmt.Errorf("adding key %s: %w", *keyID, err)
		}
	}

	// Export the keys
	if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
		return fmt.Errorf("encoding JWKS: %w", err)
	}

	return nil
}
