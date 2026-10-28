package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"threat-exchange/internal/apperror"
	"threat-exchange/internal/domain"
	"threat-exchange/internal/service"

	"github.com/stretchr/testify/require"
)

const md5 = "d41d8cd98f00b204e9800998ecf8427e"

type repositoryStub struct {
	create func(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
	get    func(context.Context, string) (*domain.Threat, error)
	update func(context.Context, string, domain.ThreatInput) (*domain.Threat, error)
}

func (r *repositoryStub) Create(ctx context.Context, hash string, input domain.ThreatInput) (*domain.Threat, error) {
	return r.create(ctx, hash, input)
}
func (r *repositoryStub) Get(ctx context.Context, hash string) (*domain.Threat, error) {
	return r.get(ctx, hash)
}
func (r *repositoryStub) Update(ctx context.Context, hash string, input domain.ThreatInput) (*domain.Threat, error) {
	return r.update(ctx, hash, input)
}

func TestCreateNormalizesWithoutMutatingCaller(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("AB", 32)
	input := domain.ThreatInput{Name: "  Trojan.Example  ", Source: " analysis ", SHA256: &hash}
	repository := &repositoryStub{create: func(_ context.Context, gotHash string, got domain.ThreatInput) (*domain.Threat, error) {
		require.Equal(t, md5, gotHash)
		require.Equal(t, "Trojan.Example", got.Name)
		require.Equal(t, "analysis", got.Source)
		require.Equal(t, domain.SeverityUnknown, got.Severity)
		require.Equal(t, domain.CategoryUnknown, got.Category)
		require.Equal(t, strings.ToLower(hash), *got.SHA256)
		return &domain.Threat{MD5: gotHash, ThreatInput: got}, nil
	}}
	_, err := service.New(repository).Create(context.Background(), strings.ToUpper(md5), input)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("AB", 32), hash)
	require.Equal(t, "  Trojan.Example  ", input.Name)
}

func TestInvalidInputsNeverReachRepository(t *testing.T) {
	t.Parallel()
	invalidHash := "not-a-sha256"
	for _, tc := range []struct {
		name, hash string
		input      domain.ThreatInput
	}{
		{"NUL text", md5, domain.ThreatInput{Name: "Threat", Source: "lab\x00source"}},
		{"invalid md5", "bad", domain.ThreatInput{Name: "Threat"}},
		{"padded md5", " " + md5, domain.ThreatInput{Name: "Threat"}},
		{"empty name", md5, domain.ThreatInput{Name: " \t\n"}},
		{"long name", md5, domain.ThreatInput{Name: strings.Repeat("я", 256)}},
		{"long description", md5, domain.ThreatInput{Name: "Threat", Description: strings.Repeat("a", 4097)}},
		{"long source", md5, domain.ThreatInput{Name: "Threat", Source: strings.Repeat("a", 256)}},
		{"severity", md5, domain.ThreatInput{Name: "Threat", Severity: "extreme"}},
		{"category", md5, domain.ThreatInput{Name: "Threat", Category: "invalid"}},
		{"sha256", md5, domain.ThreatInput{Name: "Threat", SHA256: &invalidHash}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := service.New(&repositoryStub{})
			_, err := svc.Create(context.Background(), tc.hash, tc.input)
			require.ErrorIs(t, err, apperror.ErrInvalidInput)
			_, err = svc.Update(context.Background(), tc.hash, tc.input)
			require.ErrorIs(t, err, apperror.ErrInvalidInput)
		})
	}
}

func TestGetNormalizesAndPreservesRepositoryErrors(t *testing.T) {
	t.Parallel()
	for _, expected := range []error{apperror.ErrNotFound, errors.New("database unavailable")} {
		svc := service.New(&repositoryStub{get: func(_ context.Context, hash string) (*domain.Threat, error) {
			require.Equal(t, md5, hash)
			return nil, expected
		}})
		_, err := svc.Get(context.Background(), strings.ToUpper(md5))
		require.ErrorIs(t, err, expected)
	}
	_, err := service.New(&repositoryStub{}).Get(context.Background(), "bad")
	require.ErrorIs(t, err, apperror.ErrInvalidInput)
}

func TestUpdateResetsOmittedFieldsAndPreservesConflict(t *testing.T) {
	t.Parallel()
	repository := &repositoryStub{
		update: func(_ context.Context, hash string, input domain.ThreatInput) (*domain.Threat, error) {
			require.Equal(t, md5, hash)
			require.Equal(t, domain.SeverityUnknown, input.Severity)
			require.Equal(t, domain.CategoryUnknown, input.Category)
			require.Empty(t, input.Description)
			require.Empty(t, input.Source)
			require.Nil(t, input.SHA256)
			return nil, apperror.ErrNotFound
		},
		create: func(context.Context, string, domain.ThreatInput) (*domain.Threat, error) {
			return nil, apperror.ErrAlreadyExists
		},
	}
	svc := service.New(repository)
	_, err := svc.Update(context.Background(), md5, domain.ThreatInput{Name: "Updated"})
	require.ErrorIs(t, err, apperror.ErrNotFound)
	_, err = svc.Create(context.Background(), md5, domain.ThreatInput{Name: "Duplicate"})
	require.ErrorIs(t, err, apperror.ErrAlreadyExists)
}
