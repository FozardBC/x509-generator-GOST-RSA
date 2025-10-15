package pfx

type Creator interface {
	Create(certPath, keyPath, password string) ([]byte, error)
}
