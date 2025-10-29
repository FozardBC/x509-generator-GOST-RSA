package api

import (
	caDownload "html-cer-gen/internal/api/ca/downlaod"
	"html-cer-gen/internal/api/ca/update"
	"html-cer-gen/internal/api/ca/upload"
	"html-cer-gen/internal/api/cert"
	"html-cer-gen/internal/api/cert/generate"
	sberGenerator "html-cer-gen/internal/api/cert/sber/generate"
	"html-cer-gen/internal/api/home"
	"html-cer-gen/internal/api/home/sber"
	"html-cer-gen/internal/api/middlewares/requestid"
	"html-cer-gen/internal/api/pfx/pfx"
	pfxrequest "html-cer-gen/internal/api/pfx/pfxRequest"
	"html-cer-gen/internal/lib/api/log"
	"html-cer-gen/internal/services/generator/gost"
	certgen "html-cer-gen/internal/services/generator/rsa"
	gostPGX "html-cer-gen/internal/services/pfx/gost"
	rsaPFX "html-cer-gen/internal/services/pfx/rsa"
	sberRsaGen "html-cer-gen/internal/services/sberGen/generate/rsa"
	"log/slog"

	"github.com/thinkerou/favicon"

	"github.com/gin-gonic/gin"
)

type API struct {
	Router     *gin.Engine
	Log        *slog.Logger
	rsaGen     *certgen.RSACertificateGenerator
	gostGen    *gost.GostCertificateGenerator
	sberGen    *sberRsaGen.SberRSACertificateGenerator
	pfxGenRSA  *rsaPFX.Creator
	pfxGenGOST *gostPGX.Creator
}

func New(log *slog.Logger) *API {
	return &API{
		Router:     gin.New(),
		rsaGen:     certgen.New(log),
		gostGen:    gost.New(log),
		Log:        log,
		pfxGenRSA:  rsaPFX.New(log),
		pfxGenGOST: gostPGX.New(log),
		sberGen:    sberRsaGen.New(log),
	}
}

func (api *API) Setup() {

	api.Router.LoadHTMLGlob("templates/*")
	api.Router.Static("/static", "./static")

	api.Router.Use(requestid.RequestIdMidlleware())
	api.Router.Use(gin.LoggerWithFormatter(log.Logging))
	api.Router.Use(favicon.New("./static/favicon.ico"))

	api.Router.GET("/", home.New(api.Log))
	api.Router.GET("/sber", sber.New(api.Log))

	api.Router.POST("/generate", generate.New(api.Log, api.rsaGen, api.gostGen))
	api.Router.POST("/sber/generate", sberGenerator.New(api.Log, api.sberGen))

	api.Router.GET("/download/:reqid", cert.New(api.Log))
	api.Router.GET("/ca/download/:caName", caDownload.New(api.Log))

	api.Router.GET("/update/ca", update.New(api.Log))
	api.Router.POST("/upload/ca", upload.New(api.Log))

	api.Router.POST("/pfx", pfx.New(api.Log, api.pfxGenRSA, api.pfxGenGOST)) // ПОМЕНЯТЬ НА GET
	api.Router.GET("/pfx/:reqid", pfxrequest.New(api.Log, api.pfxGenRSA, api.pfxGenGOST))

	// v1.POST("/products", add.New(api.Log, api.Storage, api.Imager))
	// v1.DELETE("/products/:id", delHandler.New(api.Log, api.Storage, api.Imager))
	// v1.GET("/products", get.New(api.Log, api.Storage))
	// v1.GET("/products/picture/:id", pic.New(api.Log, api.Imager))
	// v1.GET("/swagger/*any", gin.WrapH(httpSwagger.Handler()))

}
