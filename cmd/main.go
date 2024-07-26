package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/uuid"
	awspkg "github.com/gouthamkn/loadsimulator/pkg/aws"
	"github.com/gouthamkn/loadsimulator/pkg/csp"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	logLevel            string
	configFilePath      string
	cleanupAWSResources bool
	cleanupCSPResources bool
	wg                  sync.WaitGroup
)

type TestData struct {
	CSPURL           string                `yaml:"csp_url,omitempty"`
	CSPToken         string                `yaml:"csp_token,omitempty"`
	DrasIP           string                `yaml:"dras_ip,omitempty"`
	TestWaitDuration time.Duration         `yaml:"test_wait_duration,omitempty"`
	EC2Config        *EC2Config            `yaml:"ec2_config,omitempty"`
	Credential       *csp.Credential       `yaml:"credential,omitempty"`
	UniversalService *csp.UniversalService `yaml:"universal_service,omitempty"`
	Endpoint         *csp.Endpoint         `yaml:"endpoint,omitempty"`
}

type EC2Config struct {
	DryRun           bool     `yaml:"dry_run,omitempty"`
	Region           string   `yaml:"region,omitempty"`
	ImageID          string   `yaml:"image_id,omitempty"`
	InstanceType     string   `yaml:"instance_type,omitempty"`
	KeyName          string   `yaml:"key_name,omitempty"`
	SubnetID         string   `yaml:"subnet_id,omitempty"`
	SecurityGroupIDs []string `yaml:"security_group_ids,omitempty"`
	UserData         string   `yaml:"user_data,omitempty"`
}

func init() {
	flag.StringVar(&logLevel, "loglevel", "info", "log level (debug, info, warn, error, fatal, panic)")
	flag.StringVar(&configFilePath, "config-file", "", "path to the config file")
	flag.BoolVar(&cleanupAWSResources, "cleanup-aws-resources", true, "Cleanup AWS resources upon script execution")
	flag.BoolVar(&cleanupCSPResources, "cleanup-csp-resources", true, "Cleanup CSP resources upon script execution")
	flag.Parse()

	log.New()

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.WithError(err).Info("Invalid log level specified")

	}

	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
}

func main() {
	var (
		testData = initTestData()
		c        = csp.New(testData.CSPURL, testData.CSPToken)
		a        = awspkg.New(
			awspkg.WithDryRun(testData.EC2Config.DryRun),
			awspkg.WithRegion(testData.EC2Config.Region),
			awspkg.WithImageID(testData.EC2Config.ImageID),
			awspkg.WithInstanceType(testData.EC2Config.InstanceType),
			awspkg.WithKeyName(testData.EC2Config.KeyName),
			awspkg.WithSubnetID(testData.EC2Config.SubnetID),
			awspkg.WithSecurityGroupIDs(aws.StringSlice(testData.EC2Config.SecurityGroupIDs)),
			awspkg.WithUserData(testData.EC2Config.UserData),
		)
	)

	// Create Credential
	credentialResp, err := c.CreateCredential(
		testData.Credential,
	)
	if err != nil {
		return
	}

	testData.Credential.ID = credentialResp.Results.ID
	log.Infof("successfully created credential with ID: %s", credentialResp.Results.ID)

	// Deferred Delete of Credential
	if cleanupCSPResources {
		defer func(credentialID string) {
			err := c.DeleteCredential(credentialID)
			if err != nil {
				log.WithError(err).Errorf("failed to delete credential: %s", credentialID)
			} else {
				log.Infof("successfully deleted credential: %s", credentialID)
			}

		}(credentialResp.Results.ID)
	}

	// Create UniversalService
	universalServiceResp, err := c.CreateUniversalService(
		testData.UniversalService,
	)
	if err != nil {
		return
	}

	universalServiceID := strings.Split(universalServiceResp.Result.ID, "/")

	testData.UniversalService.ID = universalServiceID[len(universalServiceID)-1]
	log.Infof("successfully created universalService with ID: %s", testData.UniversalService.ID)

	// Deferred Delete of UniversalService
	if cleanupCSPResources {
		defer func(universalServiceID string) {
			err := c.DeleteUniversalService(universalServiceID)
			if err != nil {
				log.WithError(err).Errorf("failed to delete universalService: %s", universalServiceID)
			} else {
				log.Infof("successfully deleted universalService: %s", universalServiceID)
			}
		}(testData.UniversalService.ID)
	}

	// Create Endpoint
	endpointResp, err := c.CreateEndpoint(
		&csp.Endpoint{
			Name:               testData.Endpoint.Name,
			ServiceIP:          testData.Endpoint.ServiceIP,
			ServiceLocation:    testData.Endpoint.ServiceLocation,
			Size:               testData.Endpoint.Size,
			UniversalServiceID: testData.UniversalService.ID,
		},
	)
	if err != nil {
		return
	}

	endpointID := strings.Split(endpointResp.Result.ID, "/")

	testData.Endpoint.ID = endpointID[len(endpointID)-1]
	log.Infof("successfully created endpoint with ID: %s", testData.Endpoint.ID)

	// Deferred Delete of Endpoint
	if cleanupCSPResources {
		defer func(endpointID string) {
			err := c.DeleteEndpoint(endpointID)
			if err != nil {
				log.WithError(err).Errorf("failed to delete endpoint: %s", endpointID)
			} else {
				log.Infof("successfully deleted endpoint: %s", endpointID)
			}

		}(testData.Endpoint.ID)
	}

	// Create Locations
	locationIDs := make([]string, 0, testData.Endpoint.NumLocationsToGenerate)
	for i := 0; i < testData.Endpoint.NumLocationsToGenerate; i++ {
		locationResp, err := c.CreateLocation(
			&csp.Location{
				Name:      uuid.NewString(),
				Latitude:  "39.7837304",
				Longitude: "-100.445882",
				Address: &csp.Address{
					Country:  "United States",
					PostCode: "20912",
				},
			},
		)
		if err != nil {
			return
		}

		locationID := strings.Split(locationResp.Result.ID, "/")

		locationIDs = append(locationIDs, locationID[len(locationID)-1])
		log.Infof("successfully created location with ID: %s", locationID[len(locationID)-1])

		// Deferred Delete of Location
		if cleanupCSPResources {
			defer func(locationID string) {
				err := c.DeleteLocation(locationID)
				if err != nil {
					log.WithError(err).Errorf("failed to delete location: %s", locationID)
				} else {
					log.Infof("successfully deleted location: %s", locationID)
				}
			}(locationID[len(locationID)-1])
		}
	}

	d := make([]deferedFunc, 0)
	// Create AccessLocations
	for _, locationID := range locationIDs {
		for _, accessLocation := range testData.Endpoint.AccessLocations {
			accessLocationResp, err := c.CreateAccessLocation(
				&csp.AccessLocation{
					LocationID:     locationID,
					CredentialID:   testData.Credential.ID,
					EndpointID:     testData.Endpoint.ID,
					Description:    accessLocation.Description,
					Tags:           accessLocation.Tags,
					WANIPAddresses: accessLocation.WANIPAddresses,
					LANSubnets:     accessLocation.LANSubnets,
				},
			)
			if err != nil {
				return
			}

			accessLocationID := strings.Split(accessLocationResp.Result.ID, "/")

			accessLocation.ID = accessLocationID[len(accessLocationID)-1]
			log.Infof("successfully created accessLocation with ID: %s", accessLocation.ID)

			// Deferred Delete of AccessLocation
			if cleanupCSPResources {
				d = append(d, deferedFunc{entityType: deferedEntity_AccessLocation, entityValue: accessLocation.ID})
			}

			wg.Add(1)
			go createAccessLocationAndAssociateEC2Instance(
				log.WithField("request_id", uuid.New()),
				&wg,
				locationID,
				testData,
				c,
				a,
				*accessLocation,
				accessLocationResp.Result.Identity,
				endpointResp,
				&d,
			)
		}
	}

	wg.Wait()

	time.Sleep(testData.TestWaitDuration)
	log.Info("test duration completed, cleaning up resources")

	cleanup(c, a, d)
}

func initTestData() *TestData {
	testData := &TestData{}

	yamlFile, err := os.ReadFile(configFilePath)
	if err != nil {
		log.WithError(err).Error("failed to read config file")
		os.Exit(1)
	}

	err = yaml.Unmarshal(yamlFile, testData)
	if err != nil {
		log.WithError(err).Error("Failed to unmarshal config file")
		os.Exit(1)
	}

	log.Debug("successfully parsed config file")

	return testData
}

func createAccessLocationAndAssociateEC2Instance(
	log *logrus.Entry,
	wg *sync.WaitGroup,
	locationID string,
	testData *TestData,
	c *csp.CSP,
	a *awspkg.AWS,
	accessLocation csp.AccessLocation,
	accessLocationIdentity string,
	endpointResp *csp.EndpointResponse,
	deferedFuncs *[]deferedFunc,
) {
	defer wg.Done()

	// Template init
	var userData bytes.Buffer
	userDataTemplate, err := template.New("userdata").Parse(testData.EC2Config.UserData)
	if err != nil {
		log.WithError(err).Error("failed to parse template")
		return
	}

	// Create EC2 instance and fetch runRes.Instances[0].PublicIpAddress
	data := struct {
		RemoteIP  string // accessIP of the endpoint response cnames
		ManagedIP string // ServiceIP of the endpoint response
		PSK       string // PSK passed in the secret? (line 25) credential.keyData.psk
		LeftID    string // Identity from access location response
		DrasIP    string // IP address to be passed to DHCP_HELPER
	}{
		RemoteIP:  endpointResp.Result.CNames[0],
		ManagedIP: endpointResp.Result.ServiceIP,
		PSK:       testData.Credential.KeyData["psk"],
		LeftID:    accessLocationIdentity,
		DrasIP:    testData.DrasIP,
	}
	err = userDataTemplate.Execute(&userData, data)
	if err != nil {
		log.WithError(err).Error("failed to render template")
		return
	}

	a.UserData = base64.StdEncoding.EncodeToString(userData.Bytes())

	ec2Instance, err := a.CreateEC2Instance()
	if err != nil {
		return
	}

	// Terminate ec2 instance after the expiry of waitTime
	if cleanupAWSResources {
		*deferedFuncs = append(*deferedFuncs, deferedFunc{entityType: deferedEntity_TerminateEC2Instance, entityValue: *ec2Instance.InstanceId})
	}

	// Allocate IP address
	allocationID, err := a.AllocateIPAddress()
	if err != nil {
		return
	}

	// Release IP Address
	if cleanupAWSResources {
		*deferedFuncs = append(*deferedFuncs, deferedFunc{entityType: deferedEntity_ReleaseIPAddress, entityValue: *allocationID})
	}

	// Associate IP address with the instance
	associationID, err := a.AssociateIPAddress(ec2Instance.InstanceId, allocationID)
	if err != nil {
		return
	}

	// Dissociate IP address
	if cleanupAWSResources {
		*deferedFuncs = append(*deferedFuncs, deferedFunc{entityType: deferedEntity_DisassociateIPAddress, entityValue: *associationID})
	}

	ec2Instance, err = a.GetInstance(*ec2Instance.InstanceId)
	if err != nil {
		return
	}

	// Update the accessLocation with the publicIP address of the EC2 instance
	_, err = c.UpdateAccessLocation(
		accessLocation.ID,
		&csp.AccessLocation{
			LocationID:     locationID,
			CredentialID:   testData.Credential.ID,
			EndpointID:     testData.Endpoint.ID,
			Description:    accessLocation.Description,
			Tags:           accessLocation.Tags,
			WANIPAddresses: []string{*ec2Instance.PublicIpAddress},
			LANSubnets:     accessLocation.LANSubnets,
		},
	)
	if err != nil {
		return
	}
	log.Info("successfully updated WAN IP Address in accessLocation")
}

type deferedEntity int

const (
	deferedEntity_AccessLocation deferedEntity = iota
	deferedEntity_TerminateEC2Instance
	deferedEntity_ReleaseIPAddress
	deferedEntity_DisassociateIPAddress
)

type deferedFunc struct {
	entityType  deferedEntity
	entityValue string
}

func cleanup(
	c *csp.CSP,
	a *awspkg.AWS,
	deferedFuncs []deferedFunc,
) {
	for i := len(deferedFuncs) - 1; i >= 0; i-- {
		switch deferedFuncs[i].entityType {
		case deferedEntity_AccessLocation:
			err := c.DeleteAccessLocation(deferedFuncs[i].entityValue)
			if err != nil {
				log.WithError(err).Errorf("failed to delete accessLocation: %s", deferedFuncs[i].entityValue)
			} else {
				log.Infof("successfully deleted accessLocation: %s", deferedFuncs[i].entityValue)
			}
		case deferedEntity_TerminateEC2Instance:
			a.TerminateEC2Instance(&deferedFuncs[i].entityValue)
		case deferedEntity_ReleaseIPAddress:
			a.ReleaseIPAddress(&deferedFuncs[i].entityValue)
		case deferedEntity_DisassociateIPAddress:
			a.DisassociateIPAddress(&deferedFuncs[i].entityValue)
		default:
			log.Errorf("unknown entity type: %d", deferedFuncs[i].entityType)
		}
	}
}