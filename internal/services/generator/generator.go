package generator

import "html-cer-gen/internal/models"

const (
	CertExt = ".cer"
	KeyExt  = ".key"
)

type Generator interface {
	GenCertAndTrustCA(CertRequest *models.CertRequest, reqID string) error
}
