package mage

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
	"os"
	"path/filepath"
	"strings"
)

// Clean Remove auto-generated build artifacts
func Clean() error {
	paths := []string{"out", "internal/core/analysis_api/main/bulk_upload.zip"} // paths to remove

	// Remove __pycache__ folders
	for _, target := range pyTargets {
		err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if strings.HasSuffix(path, "__pycache__") {
				paths = append(paths, path)
			}
			return err
		})
		if err != nil {
			return err
		}
	}

	for _, pkg := range paths {
		fmt.Println("clean: rm -r " + pkg)
		if err := os.RemoveAll(pkg); err != nil {
			return err
		}
	}

	return nil
}
