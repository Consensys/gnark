**WARNING**: this is an experimental feature and might not stay in `gnark` main repository in the future. 

# gnarkd 

`gnarkd` is a `gnark` Proving / Verifying server. 
It offers synchronous gRPC APIs (use when proving time & witness size are short) and asynchronous APIs.

See [`pb/gnardk.proto`](pb/gnardk.proto) for up to date protobuf service description.

gRPC clients can be generated for multiple languages (Go, Rust, ...) see `protoc` doc for more info. 
In go: 

```
protoc --experimental_allow_proto3_optional --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative  pb/gnarkd.proto
```

## Under the hood

When `gnarkd` starts, it loads the circuits defined in `circuits/` folder. Circuits must be stored in a separate folder, under a curve subfolder.
Example: 
* `circuits/bn254/cubic` will contain `cubic.pk`, `cubic.vk` and `cubic.r1cs`.
* CircuitID (as needed in the APIs) is then `bn254/cubic` 

`gnarkd` listens on 2 distinct TCP connections: one for gRPC, one for receiving large witnesses on async calls.

On this second connection, the server expects: `jobID` | `witness` . 
* `jobID` is returned by `CreateProveJob` and is a standard UUID (RFC 4122) on 16 byte (server impl uses `github.com/google/uuid`)
* `gnarkd` knows which witness size to expect (via `r1cs.GetNbPublicWires`, `r1cs.GetNbSecretWires` and `r1cs.SizeFrElement`)


## Example client (Go)

See `client/example.go`. 