package csp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	pkgurl "net/url"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const (
	credentialPath       = "api/iam/v2/keys"
	universalServicePath = "api/universalinfra/v1/universalservices"
	endpointPath         = "api/universalinfra/v1/endpoints"
	locationPath         = "api/infra/v1/locations"
	accessLocationPath   = "api/universalinfra/v1/accesslocations"
)

var (
	ObjectType_CREDENTIAL       ObjectType = "credential"
	ObjectType_UNIVERSALSERVICE ObjectType = "universal"
	ObjectType_ENDPOINT         ObjectType = "endpoint"
	ObjectType_LOCATION         ObjectType = "location"
	ObjectType_ACCESSLOCATION   ObjectType = "accesslocation"
)

func New(cspURL, apiToken string) *CSP {
	return &CSP{
		httpClient: &http.Client{},
		cspURL:     cspURL,
		apiToken:   apiToken,
	}
}

func (c *CSP) CreateCredential(credential *Credential) (*CredentialResponse, error) {
	respBytes, err := c.create(ObjectType_CREDENTIAL, credential)
	if err != nil {
		log.WithError(err).Errorf("failed to create credential: %s", credential.Name)
		return nil, err
	}

	credentialResponse := new(CredentialResponse)

	if err := json.Unmarshal(respBytes, credentialResponse); err != nil {
		logrus.WithError(err).Errorf("failed to unmarshal credentialResponse: %s", credential.Name)
		return nil, err
	}

	return credentialResponse, nil
}

func (c *CSP) DeleteCredential(credentialID string) error {
	_, err := c.delete(ObjectType_CREDENTIAL, credentialID)
	if err != nil {
		log.WithError(err).Errorf("failed to delete credential: %s", credentialID)
	}

	return err
}

func (c *CSP) CreateUniversalService(universalService *UniversalService) (*UniversalServiceResponse, error) {
	respBytes, err := c.create(ObjectType_UNIVERSALSERVICE, universalService)
	if err != nil {
		log.WithError(err).Errorf("failed to create universalService: %s", universalService.Name)
		return nil, err
	}

	universalServiceResp := new(UniversalServiceResponse)

	if err := json.Unmarshal(respBytes, universalServiceResp); err != nil {
		logrus.WithError(err).Errorf("failed to unmarshal universalServiceResponse: %s", universalService.Name)
		return nil, err
	}

	return universalServiceResp, nil
}

func (c *CSP) DeleteUniversalService(universalServiceID string) error {
	_, err := c.delete(ObjectType_UNIVERSALSERVICE, universalServiceID)
	if err != nil {
		log.WithError(err).Errorf("failed to delete universalServiceID: %s", universalServiceID)
	}

	return err
}

func (c *CSP) CreateEndpoint(endpoint *Endpoint) (*EndpointResponse, error) {
	respBytes, err := c.create(ObjectType_ENDPOINT, endpoint)
	if err != nil {
		log.WithError(err).Errorf("failed to create endpoint %s", endpoint.Name)
		return nil, err
	}

	endpointResponse := new(EndpointResponse)
	if err := json.Unmarshal(respBytes, endpointResponse); err != nil {
		logrus.WithError(err).Errorf("failed to unmarshal endpointResponse: %s", endpoint.Name)
		return nil, err
	}

	return endpointResponse, nil
}

func (c *CSP) DeleteEndpoint(endpointID string) error {
	_, err := c.delete(ObjectType_ENDPOINT, endpointID)
	if err != nil {
		log.WithError(err).Errorf("failed to delete endpointID: %s", endpointID)
	}

	return err
}

func (c *CSP) CreateLocation(location *Location) (*LocationResponse, error) {
	respBytes, err := c.create(ObjectType_LOCATION, location)
	if err != nil {
		log.WithError(err).Errorf("failed to create location %s", location.Name)
		return nil, err
	}

	locationResponse := new(LocationResponse)
	if err := json.Unmarshal(respBytes, locationResponse); err != nil {
		logrus.WithError(err).Errorf("failed to unmarshal locationResponse: %s", location.Name)
		return nil, err
	}

	return locationResponse, nil
}

func (c *CSP) DeleteLocation(locationID string) error {
	_, err := c.delete(ObjectType_LOCATION, locationID)
	if err != nil {
		log.WithError(err).Errorf("failed to delete locationID: %s", locationID)
	}

	return err
}

func (c *CSP) CreateAccessLocation(accessLocation *AccessLocation) (*AccessLocationResponse, error) {
	respBytes, err := c.create(ObjectType_ACCESSLOCATION, accessLocation)
	if err != nil {
		return nil, err
	}

	accessLocationResponse := new(AccessLocationResponse)
	if err := json.Unmarshal(respBytes, accessLocationResponse); err != nil {
		logrus.WithError(err).Error("failed to unmarshal accessLocationResponse")
		return nil, err
	}

	return accessLocationResponse, nil
}

func (c *CSP) GetAccessLocation(accessLocationID string) (*AccessLocationResponse, error) {
	respBytes, err := c.get(ObjectType_ACCESSLOCATION, accessLocationID)
	if err != nil {
		return nil, err
	}

	getAccessLocationResponse := new(AccessLocationResponse)
	if err := json.Unmarshal(respBytes, getAccessLocationResponse); err != nil {
		logrus.WithError(err).Errorf("failed to unmarshal getAccessLocationResponse: %s", accessLocationID)
		return nil, err
	}

	return getAccessLocationResponse, nil
}

func (c *CSP) UpdateAccessLocation(accessLocationID string, accessLocation *AccessLocation) (*AccessLocationResponse, error) {
	respBytes, err := c.update(ObjectType_ACCESSLOCATION, accessLocation, accessLocationID)
	if err != nil {
		return nil, err
	}

	accessLocationResponse := new(AccessLocationResponse)
	if err := json.Unmarshal(respBytes, accessLocationResponse); err != nil {
		logrus.WithError(err).Errorf("failed to unmarshal accessLocationResponse: %s", accessLocationID)
		return nil, err
	}

	return accessLocationResponse, nil
}

func (c *CSP) DeleteAccessLocation(accessLocationID string) error {
	_, err := c.delete(ObjectType_ACCESSLOCATION, accessLocationID)
	if err != nil {
		log.WithError(err).Errorf("failed to delete accessLocationID: %s", accessLocationID)
	}

	return err
}

func (c *CSP) create(objectType ObjectType, object any) ([]byte, error) {
	req, err := c.buildRequest(http.MethodPost, objectType, object, "")
	if err != nil {
		log.WithError(err).Errorf("failed to build request to create %s", objectType)
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		log.WithError(err).Error("failed to POST request")
		return nil, err
	}

	return resp, nil
}

func (c *CSP) update(objectType ObjectType, object any, objectID string) ([]byte, error) {
	req, err := c.buildRequest(http.MethodPut, objectType, object, objectID)
	if err != nil {
		log.WithError(err).Errorf("failed to build request to update %s with ID %s", objectType, objectID)
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		log.WithError(err).Errorf("failed to PUT request to update %s with ID %s", objectType, objectID)
		return nil, err
	}

	return resp, nil
}

func (c *CSP) get(objectType ObjectType, objectID string) ([]byte, error) {
	req, err := c.buildRequest(http.MethodGet, objectType, nil, objectID)
	if err != nil {
		log.WithError(err).Errorf("failed to build request to get %s with ID %s", objectType, objectID)
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		log.WithError(err).Errorf("failed to GET %s with ID %s", objectType, objectID)
		return nil, err
	}

	return resp, nil
}

func (c *CSP) delete(objectType ObjectType, objectID string) ([]byte, error) {
	req, err := c.buildRequest(http.MethodDelete, objectType, nil, objectID)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CSP) buildRequest(method string, objectType ObjectType, object any, subPath string) (*http.Request, error) {
	var path string

	switch objectType {
	case ObjectType_CREDENTIAL:
		path = credentialPath
	case ObjectType_UNIVERSALSERVICE:
		path = universalServicePath
	case ObjectType_ENDPOINT:
		path = endpointPath
	case ObjectType_LOCATION:
		path = locationPath
	case ObjectType_ACCESSLOCATION:
		path = accessLocationPath
	}

	if subPath != "" {
		var err error
		path, err = pkgurl.JoinPath(path, subPath)
		if err != nil {
			log.WithError(err).Errorf("failed to join paths: %s, %s", path, subPath)
			return nil, err
		}
	}

	var body []byte
	var err error
	if object != nil {
		body, err = json.Marshal(object)
		if err != nil {
			log.WithError(err).Errorf("failed to marshal %s", objectType)
			return nil, err
		}
	}

	log.Debugf("built request body %s, path %s", string(body), path)

	url, err := pkgurl.JoinPath(c.cspURL, path)
	if err != nil {
		log.WithError(err).Errorf("failed to join path: %s", path)
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		log.WithError(err).Error("failed to create HTTP request")
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Token "+c.apiToken)

	return req, nil
}

func (c *CSP) doRequest(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.WithError(err).Error("failed to POST request")
		return nil, err
	}

	switch statusCode := resp.StatusCode; {
	case statusCode >= 200 && statusCode < 300:
		body, err := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		if err != nil {
			return nil, err
		}

		return body, nil

	// case statusCode == 502 || statusCode == 503 || statusCode == 504:
	// 	log.WithField("status_code", resp.StatusCode).Error("retrying...")
	// 	time.Sleep(5 * time.Second)
	// 	c.post(url, body)
	default:
		log.WithField("status_code", resp.StatusCode).Errorf("received unexpected status code for path %s", req.URL)

		body, err := io.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err == nil {
			log.Infof("response: %s", string(body))
		} else {
			log.Infof("error: %s", err.Error())
		}

		return nil, errors.New("unexpected status code received")
	}
}
