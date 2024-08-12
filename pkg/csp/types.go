package csp

import "net/http"

type ObjectType string

type CSP struct {
	httpClient *http.Client
	cspURL     string
	apiToken   string
}

type Credential struct {
	ID       string            `yaml:"id,omitempty" json:"id,omitempty"`
	Name     string            `yaml:"name,omitempty" json:"name,omitempty"`
	SourceID string            `yaml:"source_id,omitempty" json:"source_id,omitempty"`
	Active   bool              `yaml:"active,omitempty" json:"active,omitempty"`
	KeyType  string            `yaml:"key_type,omitempty" json:"key_type,omitempty"`
	KeyData  map[string]string `yaml:"key_data,omitempty" json:"key_data,omitempty"`
}

type UniversalService struct {
	ID           string        `yaml:"id,omitempty" json:"id,omitempty"`
	Name         string        `yaml:"name,omitempty" json:"name,omitempty"`
	Description  string        `yaml:"description,omitempty" json:"description,omitempty"`
	Capabilities []*Capability `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

type Capability struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

type Endpoint struct {
	ID                     string            `yaml:"id,omitempty" json:"id,omitempty"`
	Name                   string            `yaml:"name,omitempty" json:"name,omitempty"`
	ServiceIP              string            `yaml:"service_ip,omitempty" json:"service_ip,omitempty"`
	ServiceLocation        string            `yaml:"service_location,omitempty" json:"service_location,omitempty"`
	Size                   string            `yaml:"size,omitempty" json:"size,omitempty"`
	UniversalServiceID     string            `yaml:"universal_service_id,omitempty" json:"universal_service_id,omitempty"`
	NumLocationsToGenerate int               `yaml:"num_locations_to_generate,omitempty" json:"num_locations_to_generate,omitempty"`
	Locations              []*Location       `yaml:"locations,omitempty" json:"location,omitempty"`
	AccessLocations        []*AccessLocation `yaml:"access_locations,omitempty" json:"access_location,omitempty"`
}

type Location struct {
	ID                   string   `yaml:"id,omitempty" json:"id,omitempty"`
	Name                 string   `yaml:"name,omitempty" json:"name,omitempty"`
	Latitude             string   `yaml:"latitude,omitempty" json:"latitude,omitempty"`
	Longitude            string   `yaml:"longitude,omitempty" json:"longitude,omitempty"`
	Address              *Address `yaml:"address,omitempty" json:"address,omitempty"`
	EnableManagedService bool     `yaml:"enable_managed_service,omitempty" json:"enable_managed_service,omitempty"`
}

type Address struct {
	Country  string `yaml:"country,omitempty" json:"country,omitempty"`
	PostCode string `yaml:"postCode,omitempty" json:"post_code,omitempty"`
}

type AccessLocation struct {
	ID             string            `yaml:"id,omitempty" json:"id,omitempty"`
	LocationID     string            `yaml:"location_id,omitempty" json:"location_id,omitempty"`
	CredentialID   string            `yaml:"credential_id,omitempty" json:"credential_id,omitempty"`
	EndpointID     string            `yaml:"endpoint_id,omitempty" json:"endpoint_id,omitempty"`
	Description    string            `yaml:"description,omitempty" json:"description,omitempty"`
	Tags           map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	WANIPAddresses []string          `yaml:"wan_ip_addresses,omitempty" json:"wan_ip_addresses,omitempty"`
	LANSubnets     []string          `yaml:"lan_subnets,omitempty" json:"lan_subnets,omitempty"`
	Identity       string            `yaml:"identity,omitempty" json:"identity,omitempty"`
}

type CredentialResponse struct {
	Results CredentialResults `yaml:"results,omitempty" json:"results,omitempty"`
}

type CredentialResults struct {
	ID        string            `yaml:"id,omitempty" json:"id,omitempty"`
	AccountID string            `yaml:"account_id,omitempty" json:"account_id,omitempty"`
	SourceID  string            `yaml:"source_id,omitempty" json:"source_id,omitempty"`
	Name      string            `yaml:"name,omitempty" json:"name,omitempty"`
	KeyType   string            `yaml:"key_type,omitempty" json:"key_type,omitempty"`
	KeyData   map[string]string `yaml:"key_data,omitempty" json:"key_data,omitempty"`
	Active    bool              `yaml:"active,omitempty" json:"active,omitempty"`
}

type UniversalServiceResponse struct {
	Result UniversalServiceResult `yaml:"result,omitempty" json:"result,omitempty"`
}

type UniversalServiceResult struct {
	ID           string        `yaml:"id,omitempty" json:"id,omitempty"`
	Name         string        `yaml:"name,omitempty" json:"name,omitempty"`
	Capabilities []*Capability `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

type EndpointResponse struct {
	Result EndpointResult `yaml:"result,omitempty" json:"result,omitempty"`
}

type EndpointResult struct {
	ID                 string   `yaml:"id,omitempty" json:"id,omitempty"`
	Name               string   `yaml:"name,omitempty" json:"name,omitempty"`
	ServiceLocation    string   `yaml:"service_location,omitempty" json:"service_location,omitempty"`
	ServiceIP          string   `yaml:"service_ip,omitempty" json:"service_ip,omitempty"`
	CNames             []string `yaml:"cnames,omitempty" json:"cnames,omitempty"`
	Size               string   `yaml:"size,omitempty" json:"size,omitempty"`
	UniversalServiceID string   `yaml:"universal_service_id,omitempty" json:"universal_service_id,omitempty"`
}

type LocationResponse struct {
	Result LocationResult `yaml:"result,omitempty" json:"result,omitempty"`
}

type LocationResult struct {
	ID                   string            `yaml:"id,omitempty" json:"id,omitempty"`
	Name                 string            `yaml:"name,omitempty" json:"name,omitempty"`
	Identity             string            `yaml:"identity,omitempty" json:"identity,omitempty"`
	Latitude             float32           `yaml:"latitude,omitempty" json:"latitude,omitempty"`
	Longitude            float32           `yaml:"longitude,omitempty" json:"longitude,omitempty"`
	Metadata             map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	PSKID                string            `yaml:"psk_id,omitempty" json:"pskid,omitempty"`
	EnableManagedService bool              `yaml:"enable_managed_service,omitempty" json:"enable_managed_service,omitempty"`
}

type AccessLocationResponse struct {
	Result AccessLocationResult `yaml:"result,omitempty" json:"result,omitempty"`
}

type AccessLocationResult struct {
	ID             string   `yaml:"id,omitempty" json:"id,omitempty"`
	Name           string   `yaml:"name,omitempty" json:"name,omitempty"`
	EndpointID     string   `yaml:"endpoint_id,omitempty" json:"endpoint_id,omitempty"`
	LocationID     string   `yaml:"location_id,omitempty" json:"location_id,omitempty"`
	CredentialID   string   `yaml:"credential_id,omitempty" json:"credential_id,omitempty"`
	WANIPAddresses []string `yaml:"wanip_addresses,omitempty" json:"wanip_addresses,omitempty"`
	LANSubnets     []string `yaml:"lan_subnets,omitempty" json:"lan_subnets,omitempty"`
	Identity       string   `yaml:"identity,omitempty" json:"identity,omitempty"`
}
