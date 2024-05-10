package main

import (
	"context"
	"fmt"
	"log"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const (
	keySuffixNext     = "-next"
	keySuffixCurrent  = "-current"
	keySuffixPrevious = "-previous"
)

type cli struct {
	KeyAliasPrefix string `required:"" help:"Alias prefix to use when operating on keys; Actual keys will get aliases with '-next', '-current' and '-previous' suffixes."`

	Export CmdExport `cmd:"" help:"Export KMS keys as JWKS"`
	Rotate CmdRotate `cmd:"" help:"Rotate KMS keys; will create new keys if necessary"`
}

func main() {
	var cli cli
	ctx := kong.Parse(&cli)

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("unable to load AWS config, %v", err)
	}

	ktx := &Context{
		KeyAliasPrefix: cli.KeyAliasPrefix,
		kms:            kms.NewFromConfig(cfg),
	}

	ctx.FatalIfErrorf(ctx.Run(ktx))
}

type Context struct {
	KeyAliasPrefix string
	kms            *kms.Client
}

func (c Context) keyAlias(suffix string) *string {
	ka := fmt.Sprintf("alias/%s%s", c.KeyAliasPrefix, suffix)
	return &ka
}

func ptr[T any](i T) *T {
	return &i
}
