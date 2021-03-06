package api

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
	"encoding/hex"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
)

// GetEvent retrieves a specific event
func (API) GetEvent(input *models.GetEventInput) (*models.GetEventOutput, error) {
	zap.L().Info("getting alert", zap.Any("input", input))

	binaryEventID, err := hex.DecodeString(*input.EventID)
	if err != nil {
		return nil, err
	}
	event, err := alertsDB.GetEvent(binaryEventID)
	if err != nil {
		return nil, err
	}

	return &models.GetEventOutput{
		Event: event,
	}, nil
}
