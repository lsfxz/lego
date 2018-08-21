// Package hostingde implements a DNS provider for solving the DNS-01
// challenge using hosting.de.
package hostingde

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/platform/config/env"
)

// HostingdeAPIURL represents the API endpoint to call.
// TODO: Unexport?
const HostingdeAPIURL = "https://secure.hosting.de/api/dns/v1/json"

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	authKey  string
	zoneName string
	client   *http.Client
}

type RecordsAddRequest struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type RecordsDeleteRequest struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

type ZoneConfigObject struct {
	AccountID      string `json:"accountId"`
	EmailAddress   string `json:"emailAddress"`
	ID             string `json:"id"`
	LastChangeDate string `json:"lastChangeDate"`
	MasterIP       string `json:"masterIp"`
	Name           string `json:"name"`
	NameUnicode    string `json:"nameUnicode"`
	SOAValues      struct {
		Expire      string `json:"expire"`
		NegativeTTL int    `json:"negativeTtl"`
		Refresh     int    `json:"refresh"`
		Retry       int    `json:"retry"`
		Serial      string `json:"serial"`
		TTL         int    `json:"ttl"`
	} `json:"soaValues"`
	Status                string   `json:"status"`
	TemplateValues        string   `json:"templateValues"`
	Type                  string   `json:"type"`
	ZoneTransferWhitelist []string `json:"zoneTransferWhitelist"`
}

type ZoneUpdateResponse struct {
	Errors   interface{} `json:"errors,omitempty"̀`
	Metadata interface{} `json:"metadata"̀,omitempty`
	Warnings interface{} `json:"warnings"̀,omitempty`
	Status   string      `json:"status"`
	Response struct {
		Records []struct {
			Content          string `json:"content"`
			Type             string `json:"type"`
			ID               string `json:"id"`
			LastChangeDate   string `json:"lastChangeDate"`
			Priority         string `json:"priority"`
			RecordTemplateID string `json:"recordTemplateId"`
			ZoneConfigID     string `json:"zoneConfigId"`
			TTL              int    `json:"ttl"`
		} `json:"records"`
		ZoneConfig ZoneConfigObject `json:"zoneConfig"`
	} `json:"response"`
}

type ZoneConfigSelector struct {
	Name string `json:"name"`
}

type ZoneUpdateRequest struct {
	AuthToken          string `json:"authToken"`
	ZoneConfigSelector `json:"zoneConfig"`
	RecordsToAdd       []RecordsAddRequest    `json:"recordsToAdd"`
	RecordsToDelete    []RecordsDeleteRequest `json:"recordsToDelete"`
}

// NewDNSProvider returns a DNSProvider instance configured for cloudflare.
// Credentials must be passed in the environment variables: HOSTINGDE_ZONE_NAME
// and HOSTINGDE_API_KEY
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get("HOSTINGDE_API_KEY", "HOSTINGDE_ZONE_NAME")
	if err != nil {
		return nil, fmt.Errorf("Hostingde: %v", err)
	}

	return NewDNSProviderCredentials(values["HOSTINGDE_API_KEY"], values["HOSTINGDE_ZONE_NAME"])
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for cloudflare.
func NewDNSProviderCredentials(key, zoneName string) (*DNSProvider, error) {
	if key == "" || zoneName == "" {
		return nil, errors.New("Hostingde: API key or Zone Name missing")
	}

	client := &http.Client{Timeout: 30 * time.Second}

	return &DNSProvider{
		authKey:  key,
		zoneName: zoneName,
		client:   client,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := acme.DNS01Record(domain, keyAuth)

	rec := []RecordsAddRequest{
		RecordsAddRequest{
			Type:    "TXT",
			Name:    acme.UnFqdn(fqdn),
			Content: value,
			TTL:     ttl,
		},
	}

	req := ZoneUpdateRequest{
		AuthToken: d.authKey,
		ZoneConfigSelector: ZoneConfigSelector{
			Name: d.zoneName,
		},
		RecordsToAdd:    rec,
		RecordsToDelete: []RecordsDeleteRequest{},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	// Debug:
	fmt.Printf("Cleanup: \n %#v \n", body)

	_, err = d.doRequest(http.MethodPost, "/zoneUpdate", bytes.NewReader(body))
	return err
}

// CleanUp removes the TXT record matching the specified parameters
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)

	rec := []RecordsDeleteRequest{
		RecordsDeleteRequest{
			Type:    "TXT",
			Name:    acme.UnFqdn(fqdn),
			Content: value,
		},
	}

	req := ZoneUpdateRequest{
		AuthToken: d.authKey,
		ZoneConfigSelector: ZoneConfigSelector{
			Name: d.zoneName,
		},
		RecordsToAdd:    []RecordsAddRequest{},
		RecordsToDelete: rec,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	// Debug:
	fmt.Printf("Cleanup: \n %#v \n", body)

	_, err = d.doRequest(http.MethodPost, "/zoneUpdate", bytes.NewReader(body))
	return err
}

func (d *DNSProvider) doRequest(method, uri string, body io.Reader) (ZoneUpdateResponse, error) {
	var r ZoneUpdateResponse
	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", HostingdeAPIURL, uri), body)
	if err != nil {
		return r, err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return r, fmt.Errorf("error querying Hostingde API -> %v", err)
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return r, err
	}

	if r.Status != "success" {
		strBody := "Unreadable body"
		if body, err := ioutil.ReadAll(resp.Body); err == nil {
			strBody = string(body)
		}
		return r, fmt.Errorf("Hostingde API error: the request %s sent the following response: %s", req.URL.String(), strBody)
	}

	return r, nil
}
