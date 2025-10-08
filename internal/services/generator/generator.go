package generator

import "html-cer-gen/internal/models"

type Generator interface {
	GenCertAndTrustCA(CertRequest *models.CertRequest, reqID string) error
}
