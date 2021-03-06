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
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyACM(detail gjson.Result, accountID string) []*resourceChange {
	eventName := detail.Get("eventName").Str

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awscertificatemanager.html
	if eventName == "ExportCertificate" ||
		eventName == "ResendValidationEmail" {

		zap.L().Debug("acm: ignoring event", zap.String("eventName", eventName))
		return nil
	}

	var certARN string
	switch eventName {
	case "AddTagsToCertificate", "DeleteCertificate", "RemoveTags", "RenewCertificate", "UpdateCertificateOptions":
		certARN = detail.Get("requestParameters.certificateArn").Str
	case "ImportCertificate", "RequestCertificate":
		certARN = detail.Get("responseElements.certificateArn").Str
	default:
		zap.L().Warn("acm: encountered unknown event name", zap.String("eventName", eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: accountID,
		Delete:       eventName == "DeleteCertificate",
		EventName:    eventName,
		ResourceID:   certARN,
		ResourceType: schemas.AcmCertificateSchema,
	}}
}
