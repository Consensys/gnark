module github.com/consensys/gnark

go 1.15

require (
	github.com/consensys/bavard v0.1.3
	github.com/consensys/gurvy v0.0.0
	github.com/fxamacker/cbor v1.5.1
	github.com/golang/protobuf v1.3.1
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/sys v0.0.0-20200803210538-64077c9b5642 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

replace github.com/consensys/gurvy => ../gurvy
