package provider

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config stores file references, never private key or HMAC secret contents.
type Config struct {
	SubjectIDType  string            `yaml:"subject_id_type"`
	PSUTSecretFile string            `yaml:"psut_secret_file"`
	BREG           BREGConfig        `yaml:"breg"`
	Mint           MintConfig        `yaml:"mint"`
	ClaimMap       map[string]string `yaml:"claim_map"`
	HTTP           HTTPConfig        `yaml:"http"`
	Demo           DemoConfig        `yaml:"demo"`
}
type BREGConfig struct {
	BaseURL            string   `yaml:"base_url"`
	Route              string   `yaml:"route"`
	Selector           string   `yaml:"selector"`
	SelectorField      string   `yaml:"selector_field"`
	AccessProfile      string   `yaml:"access_profile"`
	ProvisionedFields  []string `yaml:"provisioned_fields"`
	AccountCheckFields []string `yaml:"account_check_fields"`
}
type MintConfig struct {
	TokenEndpoint        string `yaml:"token_endpoint"`
	AssertionAudience    string `yaml:"assertion_audience"`
	ClientID             string `yaml:"client_id"`
	PrivateKeyFile       string `yaml:"private_key_file"`
	KeyID                string `yaml:"key_id"`
	AssertionTTLSeconds  int    `yaml:"assertion_ttl_seconds"`
	TokenCacheMaxSeconds int    `yaml:"token_cache_max_seconds"`
}
type HTTPConfig struct {
	TimeoutSeconds    int    `yaml:"timeout_seconds"`
	MaxResponseBytes  int64  `yaml:"max_response_bytes"`
	AllowInsecureHTTP bool   `yaml:"allow_insecure_http"`
	CAFile            string `yaml:"ca_file"`
}
type DemoConfig struct {
	StaticOTPEnabled bool   `yaml:"static_otp_enabled"`
	StaticOTPFile    string `yaml:"static_otp_file"`
}

func LoadConfigFromEnv() (Config, error) {
	return LoadConfig(os.Getenv("REGISTRY_ESIGNET_CONFIG_FILE"))
}
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := readBounded(path, 1<<20)
	if err != nil {
		return c, errors.New("configuration file unavailable")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if d.Decode(&c) != nil {
		return Config{}, errors.New("configuration YAML invalid")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Config{}, errors.New("configuration must contain one YAML document")
	}
	c.defaults()
	if err = c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
func (c *Config) defaults() {
	if c.SubjectIDType == "" {
		c.SubjectIDType = "uin"
	}
	if len(c.BREG.AccountCheckFields) == 0 {
		c.BREG.AccountCheckFields = []string{"uin", "status"}
	}
	if c.BREG.SelectorField == "" {
		c.BREG.SelectorField = "uin"
	}
	if c.Mint.AssertionAudience == "" {
		c.Mint.AssertionAudience = c.Mint.TokenEndpoint
	}
	if c.Mint.AssertionTTLSeconds == 0 {
		c.Mint.AssertionTTLSeconds = 120
	}
	if c.Mint.TokenCacheMaxSeconds == 0 {
		c.Mint.TokenCacheMaxSeconds = 300
	}
	if c.HTTP.TimeoutSeconds == 0 {
		c.HTTP.TimeoutSeconds = 10
	}
	if c.HTTP.MaxResponseBytes == 0 {
		c.HTTP.MaxResponseBytes = 1 << 20
	}
}
func (c Config) validate() error {
	invalid := []string{}
	check := func(ok bool, field string) {
		if !ok {
			invalid = append(invalid, field)
		}
	}
	check(validText(c.SubjectIDType), "subject_id_type")
	check(!blank(c.PSUTSecretFile), "psut_secret_file")
	check(validText(c.Mint.ClientID), "mint.client_id")
	check(!blank(c.Mint.PrivateKeyFile), "mint.private_key_file")
	check(validText(c.BREG.Route) && !strings.ContainsAny(c.BREG.Route, "/\\?#") && c.BREG.Route != "." && c.BREG.Route != "..", "breg.route")
	check(validText(c.BREG.Selector), "breg.selector")
	check(validField(c.BREG.SelectorField), "breg.selector_field")
	check(validEndpoint(c.Mint.TokenEndpoint, c.HTTP.AllowInsecureHTTP), "mint.token_endpoint")
	check(validEndpoint(c.Mint.AssertionAudience, c.HTTP.AllowInsecureHTTP), "mint.assertion_audience")
	check(validEndpoint(c.BREG.BaseURL, c.HTTP.AllowInsecureHTTP), "breg.base_url")
	check(c.Mint.AssertionTTLSeconds >= 1 && c.Mint.AssertionTTLSeconds <= 300, "mint.assertion_ttl_seconds")
	check(c.Mint.TokenCacheMaxSeconds >= 1 && c.Mint.TokenCacheMaxSeconds <= 86400, "mint.token_cache_max_seconds")
	check(c.HTTP.TimeoutSeconds >= 1 && c.HTTP.TimeoutSeconds <= 120, "http.timeout_seconds")
	check(c.HTTP.MaxResponseBytes >= 1 && c.HTTP.MaxResponseBytes <= 16<<20, "http.max_response_bytes")
	check(!c.Demo.StaticOTPEnabled || !blank(c.Demo.StaticOTPFile), "demo.static_otp_file")
	check(len(c.BREG.ProvisionedFields) > 0, "breg.provisioned_fields")
	for _, s := range c.BREG.ProvisionedFields {
		if !validField(s) {
			check(false, "breg.provisioned_fields")
			break
		}
	}
	check(len(c.BREG.AccountCheckFields) > 0, "breg.account_check_fields")
	for _, s := range c.BREG.AccountCheckFields {
		if !validField(s) || !contains(c.BREG.ProvisionedFields, s) {
			check(false, "breg.account_check_fields")
			break
		}
	}
	check(contains(c.BREG.AccountCheckFields, c.BREG.SelectorField), "breg.account_check_fields")
	for k, v := range c.ClaimMap {
		if blank(k) || (!validField(v) && v != "$psut") || k == "sub" && v != "$psut" || reservedClaim(k) {
			check(false, "claim_map")
			break
		}
	}
	if len(invalid) > 0 {
		return errors.New("configuration invalid: " + strings.Join(invalid, ", "))
	}
	return nil
}
func reservedClaim(s string) bool {
	switch s {
	case "iss", "aud", "exp", "iat", "nbf", "jti", "nonce", "auth_time", "acr", "amr", "azp", "at_hash", "c_hash", "sid", "cnf", "verified_claims":
		return true
	}
	return false
}

func validEndpoint(s string, insecure bool) bool {
	u, e := url.Parse(s)
	return e == nil && u.Host != "" && u.User == nil && u.Fragment == "" && u.RawQuery == "" && (u.Scheme == "https" || insecure && u.Scheme == "http")
}
func validField(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func blank(s string) bool { return strings.TrimSpace(s) == "" }
func readBounded(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("file unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("file invalid")
	}
	return b, nil
}
