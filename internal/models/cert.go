package models

type CertRequest struct {
	CommonName       string `form:"commonName" binding:"required" validate:"required"`
	Organization     string `form:"organization" binding:"required" validate:"required"`
	OrganizationUnit string `form:"organizationUnit"`
	Country          string `form:"country" binding:"required,len=2" validate:"required,len=2"`
	Province         string `form:"province"`
	Locality         string `form:"locality"`
	Email            string `form:"email"`

	Time                  string `form:"liveTime" binding:"required"`
	UTC                   int    `form:"utc"`
	KeyType               string `form:"keyType" binding:"required" validate:"required"`
	CertType              string `form:"certType"`
	CAName                string `form:"caName" binding:"required" validate:"required"`
	Count                 int    `form:"count" binding:"required,min=1,max=100" validate:"required,min=1,max=100"`
	AuthorityInfoAccess   string `form:"authorityInfoAccess"`
	CrlDistributionPoints string `form:"crlDistributionPoints"`
	Serial                int    `form:"serial"`
	UPN                   string `form:"upn"`
}
