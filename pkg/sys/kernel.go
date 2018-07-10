// Copyright 2017 Capsule8, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sys

import (
	"golang.org/x/sys/unix"
)

// KernelVersion returns the version of the currently running kernel in major,
// minor, patchlevel form.
func KernelVersion() (int, int, int) {
	var buf unix.Utsname
	if err := unix.Uname(&buf); err != nil {
		return 0, 0, 0
	}

	var (
		b    int
		bits [3]int
	)
	for i := 0; i < len(buf.Release) && b < len(bits); i++ {
		switch buf.Release[i] {
		case '.':
			b++
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			bits[b] = bits[b]*10 + int(buf.Release[i]) - '0'
		default:
			b = len(bits)
		}
	}

	return bits[0], bits[1], bits[2]
}
