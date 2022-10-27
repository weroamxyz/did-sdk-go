package did

var defaultConfiguration = make(map[string]interface{})

type Registry interface {
	RegisterDID() error
	UpdaterDID() error
	RevokeDID(did string) error
	ActivateDID(did string, enabled bool) error
	RevokeVC(did string, vcType string) error
	RemoveController(did string, controller string) error
	AddController(did string, controller string) error
	GetDID(string) (Document, error)
	GetContext() []string
	DIDPrefix() string
	IsVCRevoked(vcIssuer string, vcHolder string, vcType string) (bool, error)
}
