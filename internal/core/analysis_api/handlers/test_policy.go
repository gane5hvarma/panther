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
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	enginemodels "github.com/panther-labs/panther/api/gateway/analysis"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	testPolicyID   = "PolicyApiTestingPolicy"
	testResourceID = "Panther:Test:Resource:"
)

// TestPolicy runs a policy against a set of unit tests.
//
// TODO - test policies before enabling them
func TestPolicy(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseTestPolicy(request)
	if err != nil {
		return badRequest(err)
	}

	// Build the list of resources to run the policy against
	resources := make([]enginemodels.Resource, len(input.Tests))
	for i, test := range input.Tests {
		// Unmarshal resource into object form
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(test.Resource), &attrs); err != nil {
			return badRequest(fmt.Errorf("tests[%d].resource is not valid json: %s", i, err))
		}

		resources[i] = enginemodels.Resource{
			Attributes: attrs,
			ID:         testResourceID + strconv.Itoa(i),
			Type:       string(test.ResourceType),
		}
	}

	// Build the policy engine request
	testRequest := enginemodels.PolicyEngineInput{
		Policies: []enginemodels.Policy{
			{
				Body: string(input.Body),
				// Doesn't matter as we're only running one policy
				ID:            testPolicyID,
				ResourceTypes: input.ResourceTypes,
			},
		},
		Resources: resources,
	}

	// Send the request to the policy-engine
	var policyEngineResults enginemodels.PolicyEngineOutput
	client := lambda.New(awsSession)
	payload, err := jsoniter.Marshal(&testRequest)
	if err != nil {
		zap.L().Error("failed to marshal PolicyEngineInput", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	response, err := client.Invoke(&lambda.InvokeInput{FunctionName: &env.Engine, Payload: payload})

	// Handle invocation failures and lambda errors
	if err != nil || response.FunctionError != nil {
		zap.L().Error("error while invoking policy-engine lambda", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := jsoniter.Unmarshal(response.Payload, &policyEngineResults); err != nil {
		zap.L().Error("failed to unmarshal lambda response into PolicyEngineOutput", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Determine the results of the tests
	var testResults = models.TestPolicyResult{
		TestSummary: true,
		// initialize as empty slices (not null) so they serialize correctly
		TestsErrored: models.TestsErrored{},
		TestsFailed:  models.TestsFailed{},
		TestsPassed:  models.TestsPassed{},
	}
	for _, result := range policyEngineResults.Resources {
		// Determine which test case this result corresponds to. We constructed resourceID with the
		// format Panther:Test:Resource:TestNumber
		testIndex, err := strconv.Atoi(strings.Split(result.ID, ":")[3])
		if err != nil {
			// We constructed this resourceID, if it is not in the expected format it has been
			// mangled by us somehow
			zap.L().Error("unable to extract test number from test result resourceID",
				zap.String("resourceID", result.ID))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		test := input.Tests[testIndex]
		switch {
		case len(result.Errored) > 0:
			// There was an error running this test, store the error message
			testResults.TestsErrored = append(testResults.TestsErrored, &models.TestErrorResult{
				ErrorMessage: result.Errored[0].Message,
				Name:         string(test.Name),
			})
			testResults.TestSummary = false

		case len(result.Failed) > 0 && bool(test.ExpectedResult), len(result.Passed) > 0 && !bool(test.ExpectedResult):
			// The test result was not expected, so this test failed
			testResults.TestsFailed = append(testResults.TestsFailed, string(test.Name))
			testResults.TestSummary = false

		case len(result.Failed) > 0 && !bool(test.ExpectedResult), len(result.Passed) > 0 && bool(test.ExpectedResult):
			// The test result was as expected
			testResults.TestsPassed = append(testResults.TestsPassed, string(test.Name))

		default:
			// The test case had a resource type that the policy did not apply to, consider an error for now.
			testResults.TestsErrored = append(testResults.TestsErrored, &models.TestErrorResult{
				ErrorMessage: "test resource type " + string(test.ResourceType) + " is not applicable to this policy",
				Name:         string(test.Name),
			})
			testResults.TestSummary = false
		}
	}

	// Return the number of passing, failing, and error-ing tests
	return gatewayapi.MarshalResponse(&testResults, http.StatusOK)
}

func parseTestPolicy(request *events.APIGatewayProxyRequest) (*models.TestPolicy, error) {
	var result models.TestPolicy
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	if err := result.Validate(nil); err != nil {
		return nil, err
	}

	return &result, nil
}
