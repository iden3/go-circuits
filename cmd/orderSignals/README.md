# Order public signals

Read sym file of circuit and output public signals in appropriate order.

Example: 
```shell
go build && ./orderSignals -sym ~/src/circuits/build/credentialJsonLDAtomicQueryMTP/circuit.sym -signals challenge,userID,userState,claimSchema,issuerID,claimPathKey,operator,value,timestamp
```
