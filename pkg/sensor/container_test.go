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

package sensor

import (
	"testing"
)

func TestFilterContainerId(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddContainerID("alice")
	cf.AddContainerID("bob")

	pass := ContainerInfo{
		ID: "alice",
	}
	if !cf.Match(pass) {
		t.Error("No matching container ID found for alice")
	}

	fail := ContainerInfo{
		ID: "bill",
	}
	if cf.Match(fail) {
		t.Error("Unexpected matching container ID found for bill")
	}
}

func TestFilterContainerImageId(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddImageID("alice")
	cf.AddImageID("bob")

	pass := ContainerInfo{
		ID:      "pass",
		ImageID: "alice",
	}
	if !cf.Match(pass) {
		t.Error("No matching container image ID found for alice")
	}

	fail := ContainerInfo{
		ID:      "fail",
		ImageID: "bill",
	}
	if cf.Match(fail) {
		t.Error("Unexpected matching container image ID found for bill")
	}
}

func TestFilterContainerImageNames(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddImageName("alice")
	cf.AddImageName("bob")

	pass := ContainerInfo{
		ID:        "pass",
		ImageName: "alice",
	}
	if !cf.Match(pass) {
		t.Error("No matching image name found for alice")
	}

	fail := ContainerInfo{
		ID:        "fail",
		ImageName: "bill",
	}
	if cf.Match(fail) {
		t.Error("Unexpected matching image name found for bill")
	}
}

func TestFilterContainerNames(t *testing.T) {
	cf := NewContainerFilter()
	cf.AddContainerName("alice")
	cf.AddContainerName("bob")

	pass := ContainerInfo{
		ID:   "pass",
		Name: "alice",
	}
	if !cf.Match(pass) {
		t.Error("No matching container name found for alice")
	}

	fail := ContainerInfo{
		ID:   "fail",
		Name: "bill",
	}
	if cf.Match(fail) {
		t.Error("Unexpected matching container name found for bill")
	}
}
