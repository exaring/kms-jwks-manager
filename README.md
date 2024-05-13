# kms-jwks-manager

This is a simple tool to rotate a set of AWS KMS keys and generate a [JWKS (JSON Web Key Set)](https://datatracker.ietf.org/doc/html/rfc7517#section-5) from them.

## Installation

The easiest to install is to use [go](https://golang.org/):

```bash
$ go install github.com/exaring/kms-jwks-manager
```

## Usage

### Bootstrapping and rotation

The following will create three KMS keys with three respective aliases: `EXAMPLE-current`, `EXAMPLE-next` and `EXAMPLE-previous`.

```bash
$ kms-jwks-manager --key-alias-prefix=EXAMPLE rotate
```

If the keys already exist, the tool will rotate them:
- `next` becomes `current`
- the `previous` key is scheduled for deletion
- a new `next` key is created
- `current` becomes `previous`

### Export

The following will export the JWKS to a file:

```bash
$ kms-jwks-manager --key-alias-prefix=EXAMPLE export --algorithm RS256 > jwks.json
```