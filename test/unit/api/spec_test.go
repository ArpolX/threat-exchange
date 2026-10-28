package api_test

import (
	"testing"

	"threat-exchange/api"

	"github.com/stretchr/testify/require"
)

func TestSpecificationIsValid(t *testing.T) {
	_, err := api.LoadSpecification()
	require.NoError(t, err)
}
