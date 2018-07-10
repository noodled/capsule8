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
	"os"

	"golang.org/x/sys/unix"

	"github.com/golang/glog"
)

// MountTempFS mounts a filesystem. It is primarily a wrapper around unix.Mount,
// but it also ensures that the mountpoint exists before attempting to mount to
// it.
func MountTempFS(source string, target string, fstype string, flags uintptr, data string) error {
	// Make sure that `target` exists.
	err := os.MkdirAll(target, 0500)
	if err != nil {
		glog.V(2).Infof("Couldn't create temp %s mountpoint: %s", fstype, err)
		return err
	}

	err = unix.Mount(source, target, fstype, flags, data)
	if err != nil {
		glog.V(2).Infof("Couldn't mount %s on %s: %s", fstype, target, err)
		return err
	}

	return nil
}

// UnmountTempFS unmounts a filesystem. It is primarily a wrapper around
// unix.Unmount, but it also removes the mountpoint after the filesystem
// is unmounted.
func UnmountTempFS(dir string, fstype string) error {
	err := unix.Unmount(dir, 0)
	if err != nil {
		glog.V(2).Infof("Couldn't unmount %s at %s: %s", fstype, dir, err)
		return err
	}

	err = os.Remove(dir)
	if err != nil {
		glog.V(2).Infof("Couldn't remove %s: %s", dir, err)
		return err
	}

	return nil
}
