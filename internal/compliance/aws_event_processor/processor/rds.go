package processor

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
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyRDS(detail gjson.Result, accountID string) []*resourceChange {
	eventName := detail.Get("eventName").Str

	if strings.HasSuffix(eventName, "DBCluster") || // 9 APIs
		strings.HasSuffix(eventName, "ParameterGroup") || // 10 APIs
		strings.HasSuffix(eventName, "Subscription") || // 5 APIs
		strings.HasSuffix(eventName, "OptionGroup") || // 4 APIs
		strings.HasSuffix(eventName, "GlobalCluster") || // 4 APIs
		strings.HasSuffix(eventName, "ClusterSnapshot") || // 3 APIs
		eventName == "CreateDBClusterEndpoint" ||
		eventName == "DeleteDBClusterEndpoint" ||
		eventName == "CreateDBSecurityGroup" ||
		eventName == "DeleteDBSecurityGroup" ||
		eventName == "AuthorizeDBSecurityGroupIngress" ||
		eventName == "DeleteDBSubnetGroup" ||
		eventName == "DownloadDBLogFilePortion" ||
		eventName == "ModifyCurrentDBClusterCapacity" ||
		eventName == "ModifyDBClusterEndpoint" ||
		eventName == "ModifyDBClusterSnapshotAttribute" ||
		eventName == "RestoreDBClusterFromS3" ||
		eventName == "RestoreDBClusterFromSnapshot" ||
		eventName == "RestoreDBClusterToPointInTime" ||
		eventName == "RevokeDBSecurityGroupIngress" ||
		eventName == "StartActivityStream" ||
		eventName == "StopActivityStream" {

		zap.L().Debug("rds: ignoring event", zap.String("eventName", eventName))
		return nil
	}

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonrds.html
	region := detail.Get("awsRegion").Str
	rdsARN := arn.ARN{
		Partition: "aws",
		Service:   "rds",
		Region:    region,
		AccountID: accountID,
		Resource:  "db:",
	}
	switch eventName {
	case "AddRoleToDBInstance", "CreateDBInstance", "CreateDBSnapshot", "DeleteDBInstance", "ModifyDBInstance",
		"PromoteReadReplica", "RebootDBInstance", "RemoveRoleFromDBInstance", "RestoreDBInstanceFromDBSnapshot",
		"RestoreDBInstanceFromS3", "StartDBInstance", "StopDBInstance":
		rdsARN.Resource += detail.Get("requestParameters.dBInstanceIdentifier").Str
	case "AddTagsToResource", "RemoveTagsFromResource":
		resourceARN, err := arn.Parse(detail.Get("requestParameters.resourceName").Str)
		if err != nil {
			zap.L().Error("rds: error parsing ARN", zap.String("eventName", eventName), zap.Error(err))
		}
		if strings.HasPrefix(resourceARN.Resource, "db:") {
			rdsARN = resourceARN
			break
		}
		return nil
	case "ApplyPendingMaintenanceAction":
		// Similar to AddTagsToResource except that it uses a different parameter name
		resourceARN, err := arn.Parse(detail.Get("requestParameters.resourceIdentifier").Str)
		if err != nil {
			zap.L().Error("rds: error parsing ARN", zap.String("eventName", eventName), zap.Error(err))
			return nil
		}
		if strings.HasPrefix(resourceARN.Resource, "db:") {
			rdsARN = resourceARN
			break
		}
		return nil
	case "CopyDBSnapshot", "DeleteDBSnapshot", "ModifyDBSnapshot":
		// Similar to the common case, but looking at the responseElements
		rdsARN.Resource += detail.Get("responseElements.dBSnapshot.dBInstanceIdentifier").Str
	case "CreateDBInstanceReadReplica":
		return []*resourceChange{{
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.dBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}, {
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.sourcedBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}}
	case "CreateDBSubnetGroup", "ModifyDBSubnetGroup":
		// If we create an RDS DBSubnetGroup resource, we will need to update this to scan that as well
		return []*resourceChange{{
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceID: arn.ARN{
				Partition: "aws",
				Service:   "ec2",
				Region:    region,
				AccountID: accountID,
				Resource:  "vpc/" + detail.Get("responseElements.dBSubnetGroup.vpcId").Str,
			}.String(),
			ResourceType: schemas.Ec2VpcSchema,
		}}
	case "DeleteDBInstanceAutomatedBackup":
		rdsARN.Resource += detail.Get("responseElements.dBInstanceAutomatedBackup.dBInstanceIdentifier").Str
	case "ModifyDBSnapshotAttribute":
		// Since we can't link this back to the corresponding RDS Instance, we need to do a full
		// RDS instance scan for now. With a linking table or resource lookups + snapshot resource
		// we could avoid this.
		return []*resourceChange{{
			AwsAccountID: accountID,
			EventName:    eventName,
			Region:       region,
			ResourceType: schemas.RDSInstanceSchema,
		}}
	case "RestoreDBInstanceToPointInTime":
		// Similar to CreateDBInstanceReadReplica but with different field names
		return []*resourceChange{{
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.targetdBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}, {
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.sourcedBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}}
	default:
		zap.L().Warn("rds: encountered unknown event name", zap.String("eventName", eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: accountID,
		Delete:       eventName == "DeleteDBInstance",
		EventName:    eventName,
		ResourceID:   rdsARN.String(),
		ResourceType: schemas.RDSInstanceSchema,
	}}
}
