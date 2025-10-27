package identity

type DidDoc struct {
	Context             []string                   `json:"@context"`
	Id                  string                     `json:"id"`
	AlsoKnownAs         []string                   `json:"alsoKnownAs"`
	VerificationMethods []DidDocVerificationMethod `json:"verificationMethod"`
	Service             []DidDocService            `json:"service"`
}

type DidDocVerificationMethod struct {
	Id                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type DidDocService struct {
	Id              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type DidData struct {
	Did                 string                      `json:"did"`
	VerificationMethods map[string]string           `json:"verificationMethods"`
	RotationKeys        []string                    `json:"rotationKeys"`
	AlsoKnownAs         []string                    `json:"alsoKnownAs"`
	Services            map[string]OperationService `json:"services"`
}

type OperationService struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

type DidLog []DidLogEntry

type DidLogEntry struct {
	Sig                 string                      `json:"sig"`
	Prev                *string                     `json:"prev"`
	Type                string                      `json:"string"`
	Services            map[string]OperationService `json:"services"`
	AlsoKnownAs         []string                    `json:"alsoKnownAs"`
	RotationKeys        []string                    `json:"rotationKeys"`
	VerificationMethods map[string]string           `json:"verificationMethods"`
}

type DidAuditEntry struct {
	Did       string      `json:"did"`
	Operation DidLogEntry `json:"operation"`
	Cid       string      `json:"cid"`
	Nullified bool        `json:"nullified"`
	CreatedAt string      `json:"createdAt"`
}

type DidAuditLog []DidAuditEntry
