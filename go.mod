module github.com/iden3/go-circuits

go 1.17

require (
	github.com/iden3/go-iden3-core v0.1.1-0.20220923135459-cda2655fb250
	github.com/iden3/go-iden3-crypto v0.0.13
	github.com/iden3/go-merkletree-sql v1.0.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

retract (
	// incorrect versions published too early
	[v0.12.0, v0.12.1]
	v0.11.0
	v0.10.0
)
