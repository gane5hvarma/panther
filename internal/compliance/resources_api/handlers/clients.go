package handlers

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"net/http"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	complianceapi "github.com/panther-labs/panther/api/gateway/compliance/client"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	env envConfig

	awsSession   *session.Session
	dynamoClient dynamodbiface.DynamoDBAPI
	sqsClient    sqsiface.SQSAPI

	httpClient       *http.Client
	complianceClient *complianceapi.PantherCompliance
)

type envConfig struct {
	ComplianceAPIHost string `required:"true" split_words:"true"`
	ComplianceAPIPath string `required:"true" split_words:"true"`
	ResourcesQueueURL string `required:"true" split_words:"true"`
	ResourcesTable    string `required:"true" split_words:"true"`
}

// Setup parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	dynamoClient = dynamodb.New(awsSession)
	sqsClient = sqs.New(awsSession)

	httpClient = gatewayapi.GatewayClient(awsSession)
	complianceClient = complianceapi.NewHTTPClientWithConfig(
		nil, complianceapi.DefaultTransportConfig().
			WithHost(env.ComplianceAPIHost).
			WithBasePath("/"+env.ComplianceAPIPath))
}
