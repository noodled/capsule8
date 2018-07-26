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
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// KernelTextSymbolNames returns a mapping of kernel symbols in the text
// segment. For each symbol in the map, the key is the source name for the
// symbol, and the value is the actual linker name that should be used for
// things like kprobes.
func (fs *FileSystem) KernelTextSymbolNames() (map[string]string, error) {
	filename := filepath.Join(fs.MountPoint, "kallsyms")
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	symbols := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Only record symbols in text segments
		if fields[1] != "t" && fields[1] != "T" {
			continue
		}
		// strings.Split will always return a slice with at least one
		// element unless both arguments are the empty string. No need
		// to check len(parts) before using parts[0]
		parts := strings.Split(fields[2], ".")
		_, exists := symbols[parts[0]]
		// Add this as a symbol if no symbol already exists with name,
		// or if this is an untouched symbol (i.e. no '.' in the name)
		if !exists || len(parts) == 1 {
			symbols[parts[0]] = fields[2]
		}
	}

	return symbols, nil
}
