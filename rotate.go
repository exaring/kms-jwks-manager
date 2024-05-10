package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type CmdRotate struct {
	MinimumAge time.Duration `help:"Minimum age the 'current' key must have to be considered for rotation." default:"24h"`
	Force      bool          `help:"Force rotation of keys regardless of age."`

	KeySpec string `help:"Key specification to use for new keys." default:"RSA_2048"`
}

// Performs a key rotation operation.
// "current" key becomes "previous" and is scheduled for deletion.
// "next" key becomes "current".
// A new key is created with the "next" alias.
func (r *CmdRotate) Run(ktx *Context) error {
	keyCurrent, err := r.getOrCreateKMSKey(ktx, keySuffixCurrent)
	if err != nil {
		return fmt.Errorf("getting current key: %w", err)
	}

	if time.Since(*keyCurrent.KeyMetadata.CreationDate) < r.MinimumAge && !r.Force {
		return fmt.Errorf("current key %s is too young to rotate", *keyCurrent.KeyMetadata.KeyId)
	}

	keyPrevious, err := ktx.kms.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: ktx.keyAlias(keySuffixPrevious),
	})
	if notFound := new(types.NotFoundException); err != nil && !errors.As(err, &notFound) {
		return fmt.Errorf("getting previous key: %w", err)
	}

	if err := updateOrCreateAlias(ktx, keySuffixPrevious, keyCurrent.KeyMetadata.KeyId); err != nil {
		return fmt.Errorf("updating alias for previous key: %w", err)
	}

	keyNext, err := r.getOrCreateKMSKey(ktx, keySuffixNext)
	if err != nil {
		return fmt.Errorf("getting next key: %w", err)
	}

	if err := updateOrCreateAlias(ktx, keySuffixCurrent, keyNext.KeyMetadata.KeyId); err != nil {
		return fmt.Errorf("updating alias for current key: %w", err)
	}

	if _, err := ktx.kms.DeleteAlias(context.Background(), &kms.DeleteAliasInput{
		AliasName: ktx.keyAlias(keySuffixNext),
	}); err != nil {
		return fmt.Errorf("deleting next alias: %w", err)
	}

	if _, err := r.getOrCreateKMSKey(ktx, keySuffixNext); err != nil {
		return fmt.Errorf("creating new key: %w", err)
	}

	if keyPrevious != nil {
		// schedule deletion last to ensure we don't lose the key on error
		if _, err := ktx.kms.ScheduleKeyDeletion(context.Background(), &kms.ScheduleKeyDeletionInput{
			KeyId: keyPrevious.KeyMetadata.KeyId,
		}); err != nil {
			return fmt.Errorf("scheduling deletion of previous key: %w", err)
		}
	}

	return nil
}

func (r *CmdRotate) getOrCreateKMSKey(ktx *Context, keySuffix string) (*kms.DescribeKeyOutput, error) {
	keyAlias := ktx.keyAlias(keySuffix)
	dk, err := ktx.kms.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: keyAlias,
	})
	if err == nil {
		return dk, nil
	} else if notFound := new(types.NotFoundException); errors.As(err, &notFound) {
		slog.Info("Key does not exist, creating", "keyAlias", *keyAlias)
		k, err := ktx.kms.CreateKey(context.Background(), &kms.CreateKeyInput{
			KeySpec:  types.KeySpec(r.KeySpec),
			KeyUsage: types.KeyUsageTypeSignVerify, // TODO: also support encrypt/decrypt keys?
			Tags: []types.Tag{
				{
					TagKey:   ptr("ManagedBy"),
					TagValue: ptr("kms-jkws-manager"),
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("creating key: %w", err)
		}
		if _, err := ktx.kms.CreateAlias(context.Background(), &kms.CreateAliasInput{
			AliasName:   keyAlias,
			TargetKeyId: k.KeyMetadata.KeyId,
		}); err != nil {
			return nil, fmt.Errorf("creating alias for %s: %w", *k.KeyMetadata.KeyId, err)
		}
		return ktx.kms.DescribeKey(context.Background(), &kms.DescribeKeyInput{
			KeyId: keyAlias,
		})
	}
	return nil, err
}

func updateOrCreateAlias(ktx *Context, keySuffix string, keyID *string) error {
	_, err := ktx.kms.UpdateAlias(context.Background(), &kms.UpdateAliasInput{
		AliasName:   ktx.keyAlias(keySuffix),
		TargetKeyId: keyID,
	})
	if notFound := new(types.NotFoundException); errors.As(err, &notFound) {
		_, err := ktx.kms.CreateAlias(context.Background(), &kms.CreateAliasInput{
			AliasName:   ktx.keyAlias(keySuffix),
			TargetKeyId: keyID,
		})
		if err != nil {
			return fmt.Errorf("creating %s alias: %w", keySuffix, err)
		}
	} else if err != nil {
		return fmt.Errorf("updating %s alias: %w", keySuffix, err)
	}

	return nil
}
