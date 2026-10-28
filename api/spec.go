package api

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.1 -generate types -package api -o dto_gen.go openapi.yaml
//go:generate sh -c "sed '/^[[:space:]]*[/][/]/d' dto_gen.go > dto_gen.go.tmp && mv dto_gen.go.tmp dto_gen.go"
//go:generate gofmt -w dto_gen.go

import (
	"context"
	_ "embed"

	"github.com/getkin/kin-openapi/openapi3"
)

//go:embed openapi.yaml
var specification []byte

func LoadSpecification() (*openapi3.T, error) {
	spec, err := openapi3.NewLoader().LoadFromData(specification)
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(context.Background()); err != nil {
		return nil, err
	}
	return spec, nil
}
