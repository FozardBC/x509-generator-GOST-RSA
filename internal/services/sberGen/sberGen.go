package sbergen

import "html-cer-gen/internal/models"

type SberGenerator interface {
	GenCertAndTrustCA(CertRequest *models.SberCertRequest, requestid string) error
}
