package acme_utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	acmeUtilsErrors "github.com/altshiftab/acme_utils/pkg/errors"
	"golang.org/x/crypto/acme"
)

func obtainCertificate(
	ctx context.Context,
	domain string,
	certificateKey *ecdsa.PrivateKey,
	orderUri string,
	client *acme.Client,
) ([][]byte, error) {
	if domain == "" {
		return nil, nil
	}

	if certificateKey == nil {
		return nil, motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilCertificateKey)
	}

	if orderUri == "" {
		return nil, motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrEmptyOrderUri)
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilClient)
	}

	certificateRequest, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}},
		certificateKey,
	)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("x509 create certificate request: %w", err))
	}
	if certificateRequest == nil {
		return nil, motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilCertificateRequest)
	}

	order, err := client.WaitOrder(ctx, orderUri)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("acme client wait order: %w", err))
	}
	if order == nil {
		return nil, motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilOrder)
	}

	finalizeURL := order.FinalizeURL
	certificateDerBlocks, _, err := client.CreateOrderCert(ctx, finalizeURL, certificateRequest, true)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("acme client create order cert: %w", err),
			finalizeURL,
		)
	}

	return certificateDerBlocks, nil
}

func authorize(ctx context.Context, authorizationUrl string, client *acme.Client, callback func(string) error) error {
	if authorizationUrl == "" {
		return motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrEmptyAuthorizationUrl)
	}

	if client == nil {
		return motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilClient)
	}

	if callback == nil {
		return motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilAuthorizeCallback)
	}

	authorization, err := client.GetAuthorization(ctx, authorizationUrl)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("acme client get authorization: %w", err))
	}
	if authorization == nil {
		return motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilAuthorization)
	}

	challenge := getChallenge(authorization)
	if challenge == nil {
		return motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilChallenge)
	}

	dnsChallengeRecordValue, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("acme client 01 dns challenge record: %w", err))
	}
	if dnsChallengeRecordValue == "" {
		return motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrEmptyDnsChallengeRecordValue)
	}

	if err := callback(dnsChallengeRecordValue); err != nil {
		return fmt.Errorf("authorization callback: %w", err)
	}

	if _, err := client.Accept(ctx, challenge); err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("acme client accept: %w", err))
	}

	authorizationUri := authorization.URI
	if _, err := client.WaitAuthorization(ctx, authorizationUri); err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("acme client wait authorization: %w", err), authorizationUri)
	}

	return nil
}

func getChallenge(authorization *acme.Authorization) *acme.Challenge {
	if authorization == nil {
		return nil
	}

	for _, candidateChallenge := range authorization.Challenges {
		if candidateChallenge == nil {
			continue
		}

		if candidateChallenge.Type == "dns-01" {
			return candidateChallenge
		}
	}

	return nil
}

func RenewCertificate(
	ctx context.Context,
	domain string,
	authorizeCallback func(string) error,
	client *acme.Client,
	certificateKey *ecdsa.PrivateKey,
) (*ecdsa.PrivateKey, [][]byte, error) {
	if domain == "" {
		return nil, nil, nil
	}

	if authorizeCallback == nil {
		return nil, nil, acmeUtilsErrors.ErrNilAuthorizeCallback
	}

	if client == nil {
		return nil, nil, acmeUtilsErrors.ErrNilClient
	}

	if certificateKey == nil {
		var err error

		curve := elliptic.P256()
		certificateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, motmedelErrors.NewWithTrace(fmt.Errorf("ecdsa generate key: %w", err))
		}
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return nil, nil, motmedelErrors.NewWithTrace(fmt.Errorf("acme client authorize order: %w", err))
	}
	if order == nil {
		return nil, nil, motmedelErrors.NewWithTrace(acmeUtilsErrors.ErrNilOrder)
	}

	orderAuthzUrls := order.AuthzURLs
	if len(orderAuthzUrls) == 0 {
		return nil, nil, acmeUtilsErrors.ErrEmptyAuthorizationUrls
	}

	authorizationUrl := orderAuthzUrls[0]
	if err := authorize(ctx, authorizationUrl, client, authorizeCallback); err != nil {
		return nil, nil, motmedelErrors.New(fmt.Errorf("authorize: %w", err), authorizationUrl)
	}

	orderUri := order.URI
	certificateBlocks, err := obtainCertificate(ctx, domain, certificateKey, orderUri, client)
	if err != nil {
		return nil, nil, motmedelErrors.New(fmt.Errorf("obtain certificate: %w", err), orderUri)
	}

	return certificateKey, certificateBlocks, nil
}
