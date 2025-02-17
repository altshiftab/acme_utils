package acme_utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
		return nil, acmeUtilsErrors.ErrNilCertificateKey
	}

	if orderUri == "" {
		return nil, acmeUtilsErrors.ErrEmptyOrderUri
	}

	if client == nil {
		return nil, acmeUtilsErrors.ErrNilClient
	}

	certificateRequest, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}},
		certificateKey,
	)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when creating a certificate request.",
			Cause:   err,
			Input:   domain,
		}
	}
	if certificateRequest == nil {
		return nil, acmeUtilsErrors.ErrNilCertificateRequest
	}

	order, err := client.WaitOrder(ctx, orderUri)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when waiting for an order.",
			Cause:   err,
			Input:   orderUri,
		}
	}
	if order == nil {
		return nil, acmeUtilsErrors.ErrNilOrder
	}

	certificateDerBlocks, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, certificateRequest, true)
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when creating certificate blocks.",
			Cause:   err,
		}
	}

	return certificateDerBlocks, nil
}

func authorize(ctx context.Context, authorizationUrl string, client *acme.Client, callback func(string) error) error {
	if authorizationUrl == "" {
		return acmeUtilsErrors.ErrEmptyAuthorizationUrl
	}

	if client == nil {
		return acmeUtilsErrors.ErrNilClient
	}

	if callback == nil {
		return acmeUtilsErrors.ErrNilAuthorizeCallback
	}

	authorization, err := client.GetAuthorization(ctx, authorizationUrl)
	if err != nil {
		return &motmedelErrors.InputError{
			Message: "An error occurred when getting an authorization response.",
			Cause:   err,
			Input:   authorizationUrl,
		}
	}
	if authorization == nil {
		return acmeUtilsErrors.ErrNilAuthorization
	}

	challenge := getChallenge(authorization)
	if challenge == nil {
		return acmeUtilsErrors.ErrNilChallenge
	}

	dnsChallengeRecordValue, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return &motmedelErrors.CauseError{
			Message: "An error occurred when obtaining the DNS challenge record value.",
			Cause:   err,
		}
	}
	if dnsChallengeRecordValue == "" {
		return acmeUtilsErrors.ErrEmptyDnsChallengeRecordValue
	}

	if err := callback(dnsChallengeRecordValue); err != nil {
		return &motmedelErrors.CauseError{
			Message: "An error occurred when calling the authorization callback.",
			Cause:   err,
		}
	}

	if _, err := client.Accept(ctx, challenge); err != nil {
		return &motmedelErrors.CauseError{
			Message: "An error occurred when accepting the challenge.",
			Cause:   err,
		}
	}

	if _, err := client.WaitAuthorization(ctx, authorization.URI); err != nil {
		return &motmedelErrors.CauseError{
			Message: "An error occurred when waiting for authorization.",
			Cause:   err,
		}
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
			return nil, nil, &motmedelErrors.InputError{
				Message: "An error occurred when generating a certificate key.",
				Cause:   err,
				Input:   curve,
			}
		}
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return nil, nil, &motmedelErrors.CauseError{
			Message: "An error occurred when authorizing an order.",
			Cause:   err,
		}
	}
	if order == nil {
		return nil, nil, acmeUtilsErrors.ErrNilOrder
	}

	orderAuthzUrls := order.AuthzURLs
	if len(orderAuthzUrls) == 0 {
		return nil, nil, acmeUtilsErrors.ErrEmptyAuthorizationUrls
	}

	authorizationUrl := orderAuthzUrls[0]
	if err := authorize(ctx, authorizationUrl, client, authorizeCallback); err != nil {
		return nil, nil, &motmedelErrors.InputError{
			Message: "An error occurred when authorizing.",
			Cause:   err,
			Input:   authorizationUrl,
		}
	}

	certificateBlocks, err := obtainCertificate(ctx, domain, certificateKey, order.URI, client)
	if err != nil {
		return nil, nil, &motmedelErrors.CauseError{
			Message: "An error occurred when obtaining the certificate.",
			Cause:   err,
		}
	}

	return certificateKey, certificateBlocks, nil
}
