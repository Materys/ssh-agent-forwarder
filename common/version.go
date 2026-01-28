// ssh-agent-forwarder, a code to authenticate ssh connections using an agent on a different machine
// Copyright (C) 2026 Riccardo Bertossa (MATERYS SRL), Sebastiano Bisacchi (MATERYS SRL)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package common

import (
	"fmt"
)

type VersionInfoData struct {
	Version uint32
	AllowedHandshakeVersions []uint32
}

func BuildVersionInfoData(version uint32, allowedVersions []uint32) *VersionInfoData {
	if allowedVersions == nil || len(allowedVersions) == 0 {
		panic("allowedVersions must contain at least one version")
	}

	if len(allowedVersions) > 1 {
		panic("multiple allowedVersions not supported yet")
	}

	return &VersionInfoData{
		Version: version,
		AllowedHandshakeVersions: allowedVersions,
	}
}

func (v *VersionInfoData) Validate(remoteVersion uint32) error {
	for _, allowed := range v.AllowedHandshakeVersions {
		if allowed == remoteVersion {
			return nil
		}
	}
	return fmt.Errorf("version %d not allowed", remoteVersion)
}