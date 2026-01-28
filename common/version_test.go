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
package common;

import (
	"testing"
)

func TestBuildVersionInfoData(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic when allowedVersions is empty, but did not panic")
		}
	}()
	_ = BuildVersionInfoData(1, []uint32{})
}

func TestBuildVersionInfoDataMultipleAllowed(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic when allowedVersions has multiple entries, but did not panic")
		}
	}()
	_ = BuildVersionInfoData(1, []uint32{1, 2})
}

func TestVersionValidation(t *testing.T) {
	vinfo := BuildVersionInfoData(1, []uint32{1})

	tests := []struct {
		remoteVersion uint32
		shouldPass    bool
	}{
		{remoteVersion: 1, shouldPass: true},
	}

	for _, test := range tests {
		err := vinfo.Validate(test.remoteVersion)
		if test.shouldPass && err != nil {
			t.Errorf("Expected version %d to pass validation, but got error: %v", test.remoteVersion, err)
		}
		if !test.shouldPass && err == nil {
			t.Errorf("Expected version %d to fail validation, but it passed", test.remoteVersion)
		}
	}
}