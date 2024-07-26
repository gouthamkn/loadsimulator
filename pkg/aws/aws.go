package aws

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	log "github.com/sirupsen/logrus"
)

type AWS struct {
	EC2Client        *ec2.EC2
	dryRun           bool
	region           string
	imageID          string
	instanceType     string
	keyName          string
	subnetID         string
	securityGroupIDs []*string
	UserData         string
}

type AWSOpt func(*AWS)

func WithDryRun(dryRun bool) AWSOpt {
	return func(a *AWS) {
		a.dryRun = dryRun
	}
}

func WithRegion(region string) AWSOpt {
	return func(a *AWS) {
		a.region = region
	}
}

func WithImageID(imageID string) AWSOpt {
	return func(a *AWS) {
		a.imageID = imageID
	}
}

func WithInstanceType(instanceType string) AWSOpt {
	return func(a *AWS) {
		a.instanceType = instanceType
	}
}

func WithKeyName(keyName string) AWSOpt {
	return func(a *AWS) {
		a.keyName = keyName
	}
}

func WithSubnetID(subnetID string) AWSOpt {
	return func(a *AWS) {
		a.subnetID = subnetID
	}
}

func WithSecurityGroupIDs(securityGroupIDs []*string) AWSOpt {
	return func(a *AWS) {
		a.securityGroupIDs = securityGroupIDs
	}
}

func WithUserData(userData string) AWSOpt {
	return func(a *AWS) {
		a.UserData = userData
	}
}

func New(opts ...AWSOpt) *AWS {
	a := &AWS{}

	for _, opt := range opts {
		opt(a)
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(a.region)},
	)
	if err != nil {
		log.WithError(err).Error("failed to create session")
		return nil
	}

	a.EC2Client = ec2.New(sess)

	return a
}

func (a *AWS) CreateEC2Instance() (*ec2.Instance, error) {
	runRes, err := a.EC2Client.RunInstances(
		&ec2.RunInstancesInput{
			DryRun:           aws.Bool(a.dryRun),
			ImageId:          aws.String(a.imageID),
			InstanceType:     aws.String(a.instanceType),
			KeyName:          aws.String(a.keyName),
			SubnetId:         aws.String(a.subnetID),
			SecurityGroupIds: a.securityGroupIDs,
			UserData:         aws.String(a.UserData),
			MinCount:         aws.Int64(1),
			MaxCount:         aws.Int64(1),
		},
	)
	if err != nil {
		log.WithError(err).Error("failed to create ec2 instance")
		return nil, err
	}

	// Wait until the instance is Running
instanceCheckLoop:
	for i := 0; i < 20; i++ {
		describeRes, err := a.EC2Client.DescribeInstances(&ec2.DescribeInstancesInput{
			DryRun: aws.Bool(a.dryRun),
			InstanceIds: []*string{
				runRes.Instances[0].InstanceId,
			},
		})
		if err != nil {
			log.WithError(err).Errorf("failed to describe ec2 instance %s", *runRes.Instances[0].InstanceId)
		}

		for _, reservation := range describeRes.Reservations {
			for _, instance := range reservation.Instances {
				if *instance.State.Name == ec2.InstanceStateNameRunning {
					runRes.Instances[0].PublicIpAddress = instance.PublicIpAddress
					break instanceCheckLoop
				}

				log.Infof(
					"waiting for instance %s to transition to %s state, currentState: %s",
					*runRes.Instances[0].InstanceId,
					ec2.InstanceStateNameRunning,
					*instance.State.Name,
				)
			}
		}

		time.Sleep(5 * time.Second)
	}

	// runRes.Instances[0].PublicIpAddress

	log.Infof("successfully created ec2 instance %s", *runRes.Instances[0].InstanceId)
	return runRes.Instances[0], nil
}

func (a *AWS) TerminateEC2Instance(instanceID *string) error {
	_, err := a.EC2Client.TerminateInstances(
		&ec2.TerminateInstancesInput{
			DryRun:      aws.Bool(a.dryRun),
			InstanceIds: []*string{instanceID},
		},
	)

	if err != nil {
		log.WithError(err).Errorf("failed to terminate ec2 instance %s", *instanceID)
		return err
	}

	log.Infof("successfully terminated ec2 instance %s", *instanceID)
	return err
}

func (a *AWS) AllocateIPAddress() (*string, error) {
	allocRes, err := a.EC2Client.AllocateAddress(
		&ec2.AllocateAddressInput{
			DryRun: aws.Bool(a.dryRun),
			Domain: aws.String("vpc"),
		},
	)

	if err != nil {
		log.WithError(err).Error("failed to allocate IP address")
		return nil, err
	}

	log.Infof("successfully allocated IP address: %s", *allocRes.AllocationId)
	return allocRes.AllocationId, nil
}

func (a *AWS) ReleaseIPAddress(allocationID *string) error {
	_, err := a.EC2Client.ReleaseAddress(
		&ec2.ReleaseAddressInput{
			DryRun:       aws.Bool(a.dryRun),
			AllocationId: allocationID,
		},
	)

	if err != nil {
		log.WithError(err).Errorf("failed to release IP address: %s", *allocationID)
		return err
	}

	log.Infof("successfully released IP address: %s", *allocationID)
	return nil
}

func (a *AWS) AssociateIPAddress(instanceID, allocationID *string) (*string, error) {
	assocRes, err := a.EC2Client.AssociateAddress(
		&ec2.AssociateAddressInput{
			DryRun:       aws.Bool(a.dryRun),
			AllocationId: allocationID,
			InstanceId:   instanceID,
		},
	)
	if err != nil {
		log.WithError(err).Errorf("failed to associate IP address to instance %s", *instanceID)
		return nil, err
	}

	log.Infof("successfully associated IP address to instance %s with associationID %s", *instanceID, *assocRes.AssociationId)
	return assocRes.AssociationId, nil
}

func (a *AWS) DisassociateIPAddress(associationID *string) error {
	_, err := a.EC2Client.DisassociateAddress(
		&ec2.DisassociateAddressInput{
			DryRun:        aws.Bool(a.dryRun),
			AssociationId: associationID,
		},
	)
	if err != nil {
		log.WithError(err).Errorf("failed to disassociate IP address %s", *associationID)
		return err
	}

	log.Infof("successfully disassociated IP address %s", *associationID)
	return nil
}

func (a *AWS) GetInstance(instanceID string) (*ec2.Instance, error) {
	result, err := a.EC2Client.DescribeInstances(
		&ec2.DescribeInstancesInput{
			InstanceIds: []*string{
				aws.String(instanceID),
			},
		},
	)

	if err != nil {
		log.WithError(err).Errorf("failed to describe instance: %s", instanceID)
		return nil, err
	}

	for _, reservation := range result.Reservations {
		return reservation.Instances[0], nil
	}

	return nil, errors.New("ec2 instance not found")
}
