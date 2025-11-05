package csr

// func New(log *slog.Logger) gin.HandlerFunc {
// 	return func(c *gin.Context) {

// 		reqID := requestid.Get(c)

// 		logHandler := log.With(
// 			slog.String("requestID", requestid.Get(c)),
// 		)

// 		selectedCa := c.Query("caName")
// 		if selectedCa == "" {
// 			selectedCa = "_"
// 		}

// 		certFile, certFileHeader, err := c.Request.FormFile("csrFile")
// 		if err != nil {
// 			logHandler.Error(err.Error())

// 			c.JSON(http.StatusBadRequest, gin.H{
// 				"error": "Не удалось получить файл сертификата." + err.Error(),
// 			})
// 			return
// 		}
// 		defer certFile.Close()

// 		// принимаем файл csr
// 		// принимаем Выбранный УЦ
// 		// отдаем .key .cer
// 	}
// }
