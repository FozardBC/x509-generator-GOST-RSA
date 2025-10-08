package generator

type Generator interface {
	GenCertAndTrustCA(
		commonName string,
		organization string,
		country string,
		timeLive string,
		UTC int,
		keyType string,
		certType string,
		caName string,
		requestid string,
		crlDistributionPoints string,
		authorityInfoAccess string,
		serial int,
	) error
}
