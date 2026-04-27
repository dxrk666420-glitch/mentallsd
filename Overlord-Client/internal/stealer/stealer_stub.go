//go:build !windows

package stealer

type Credential struct {
	Browser  string `json:"browser"`
	Profile  string `json:"profile"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Cookie struct {
	Browser  string `json:"browser"`
	Profile  string `json:"profile"`
	Host     string `json:"host"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	IsSecure bool   `json:"isSecure"`
}

type Card struct {
	Browser     string `json:"browser"`
	Profile     string `json:"profile"`
	Name        string `json:"name"`
	Number      string `json:"number"`
	ExpiryMonth int    `json:"expiryMonth"`
	ExpiryYear  int    `json:"expiryYear"`
}

type WalletFile struct {
	Wallet   string `json:"wallet"`
	Filename string `json:"filename"`
	DataB64  string `json:"dataB64"`
}

type GameToken struct {
	Game     string `json:"game"`
	Type     string `json:"type"`
	Username string `json:"username"`
	Value    string `json:"value"`
}

type Result struct {
	Credentials []Credential `json:"credentials"`
	Cookies     []Cookie     `json:"cookies"`
	Cards       []Card       `json:"cards"`
	Tokens      []string     `json:"tokens"`
	Wallets     []WalletFile `json:"wallets"`
	GameTokens  []GameToken  `json:"gameTokens"`
	Errors      []string     `json:"errors"`
}

func Run() Result {
	return Result{Errors: []string{"stealer not supported on this platform"}}
}
