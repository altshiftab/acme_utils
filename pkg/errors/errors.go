package errors

import "errors"

var (
	ErrNilClient                    = errors.New("nil client")
	ErrNilAuthorizedOrder           = errors.New("nil authorized order")
	ErrNilOrder                     = errors.New("nil order")
	ErrEmptyAuthorizationUrls       = errors.New("empty authorization urls")
	ErrNilAuthorization             = errors.New("nil authorization")
	ErrNilChallenge                 = errors.New("nil challenge")
	ErrEmptyAuthorizationUrl        = errors.New("empty authorization urls")
	ErrEmptyDnsChallengeRecordValue = errors.New("empty DNS challenge record value")
	ErrNilAuthorizeCallback         = errors.New("nil authorize callback")
	ErrNilCertificateRequest        = errors.New("nil certificate request")
	ErrEmptyOrderUri                = errors.New("empty order uri")
	ErrNilCertificateKey            = errors.New("nil certificate key")
)
