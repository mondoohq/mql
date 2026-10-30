// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsinstanceconnect

import (
	"context"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/cockroachdb/errors"
	"github.com/sethvargo/go-password/password"
	"go.mondoo.com/mql/providers/os/connection/ssh/keypair"
)

type generator struct {
	cfg aws.Config
}

func New(cfg aws.Config) *generator {
	return &generator{cfg: cfg}
}

type InstanceCredentials struct {
	InstanceId      string
	KeyPair         *keypair.SSH
	PublicDnsName   string
	PrivateDnsName  string
	PublicIpAddress string
}

// Note: target can either be the IP (ipv4) address or the instance id of the machine
func (c *generator) GenerateCredentials(target string, user string) (*InstanceCredentials, error) {
	return c.GenerateCredentialsContext(context.Background(), target, user)
}

func (c *generator) GenerateCredentialsContext(ctx context.Context, target string, user string) (*InstanceCredentials, error) {
	ec2srv := ec2.NewFromConfig(c.cfg)
	input := &ec2.DescribeInstancesInput{}
	ip := net.ParseIP(target)
	if ip != nil && ip.To4() != nil {
		filter := "ip-address"
		input.Filters = []ec2types.Filter{
			{
				Name:   &filter,
				Values: []string{target},
			},
		}
	} else {
		input.InstanceIds = []string{target}
	}
	resp, err := ec2srv.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	if len(resp.Reservations) != 1 || len(resp.Reservations[0].Instances) != 1 {
		return nil, errors.New("could not find the instance")
	}

	instance := resp.Reservations[0].Instances[0]

	// generate random passphrase
	passphrase, err := password.Generate(64, 10, 10, false, false)
	if err != nil {
		return nil, err
	}

	sshkeypair, err := keypair.NewRSAKeys(keypair.DefaultRsaBits, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	ec2ic := ec2instanceconnect.NewFromConfig(c.cfg)
	_, err = ec2ic.SendSSHPublicKey(ctx, &ec2instanceconnect.SendSSHPublicKeyInput{
		InstanceId:       instance.InstanceId,
		AvailabilityZone: instance.Placement.AvailabilityZone,
		InstanceOSUser:   aws.String(user),
		SSHPublicKey:     aws.String(string(sshkeypair.PublicKey)),
	})
	if err != nil {
		return nil, err
	}

	ic := &InstanceCredentials{
		KeyPair: sshkeypair,
	}

	if instance.PublicDnsName != nil {
		ic.PublicDnsName = *instance.PublicDnsName
	}

	if instance.PrivateDnsName != nil {
		ic.PrivateDnsName = *instance.PrivateDnsName
	}

	if instance.PublicIpAddress != nil {
		ic.PublicIpAddress = *instance.PublicIpAddress
	}

	if instance.InstanceId != nil {
		ic.InstanceId = *instance.InstanceId
	}

	return ic, nil
}
