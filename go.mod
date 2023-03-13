module github.com/iden3/go-circuits

go 1.18

require (
	github.com/iden3/go-iden3-core v1.0.1
	github.com/iden3/go-iden3-crypto v0.0.14
	github.com/iden3/go-merkletree-sql/v2 v2.0.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract (
	// incorrect versions published too early
	[v0.12.0, v0.12.1]
	v0.11.0
	v0.10.0
)
