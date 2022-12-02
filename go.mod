module github.com/iden3/go-circuits

go 1.18

require (
	github.com/iden3/go-iden3-core v0.1.1-0.20221108150644-c0b53ebc36d1
	github.com/iden3/go-iden3-crypto v0.0.13
	github.com/iden3/go-merkletree-sql/v2 v2.0.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20220126234351-aa10faf2a1f8 // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract (
	// incorrect versions published too early
	[v0.12.0, v0.12.1]
	v0.11.0
	v0.10.0
)
