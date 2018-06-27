// Copyright 2018 Capsule8, Inc.
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

package procfs

import (
	"testing"
)

func TestKernelTextSymbolNames(t *testing.T) {
	fs, err := NewFileSystem("testdata/proc")
	ok(t, err)

	expectedSymbols := map[string]string{
		"__intel_shared_reg_put_constraints": "__intel_shared_reg_put_constraints.isra.6.part.7",
		"create_dev":                         "create_dev.constprop.6",
		"cgroup_attach_task_all":             "cgroup_attach_task_all",
		"__cgroup_procs_write":               "__cgroup_procs_write",
	}

	actualSymbols, err := fs.KernelTextSymbolNames()
	ok(t, err)
	equals(t, expectedSymbols, actualSymbols)
}
