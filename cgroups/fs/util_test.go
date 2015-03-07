/*
Utility for testing cgroup operations.

Creates a mock of the cgroup filesystem for the duration of the test.
*/
package fs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/configs"
)

type cgroupTestUtil struct {
	// data to use in tests.
	CgroupData *data

	// Path to the mock cgroup directory.
	CgroupPath string

	t *testing.T
}

// Creates a new test util for the specified subsystem
func NewCgroupTestUtil(subsystem string, t *testing.T) *cgroupTestUtil {
	d := &data{
		c:      &configs.Cgroup{},
		cgroup: "/cgroup_test",
	}

	root, err := getCgroupRoot()
	if err != nil {
		t.Fatal(err)
	}

	d.root = root
	testCgroupPath, err := d.path(subsystem)
	if err != nil {
		if cgroups.IsNotFound(err) && testCgroupPath == "" {
			// IsNotFound err and empty path means subsystem not mounted
			t.Skipf("%s cgroup not mounted, skipping test.", subsystem)
		} else if !cgroups.IsNotFound(err) {
			t.Fatal(err)
		}
	}

	// Ensure the full mock cgroup path exists.
	err = os.MkdirAll(testCgroupPath, 0755)
	if err != nil {
		t.Fatal(err)
	}
	return &cgroupTestUtil{CgroupData: d, CgroupPath: testCgroupPath, t: t}
}

// FIXME: This returns cgroupTestUtil with faked cgroup path, right now is
// used by stats tests only, need to figure out a better way to test stats
// and get rid of this function.
func tempCgroupTestUtil(subsystem string, t *testing.T) *cgroupTestUtil {
	d := &data{
		c: &configs.Cgroup{},
	}
	tempDir, err := ioutil.TempDir("", subsystem)
	if err != nil {
		t.Fatal(err)
	}
	d.root = tempDir
	testCgroupPath := filepath.Join(d.root, fmt.Sprintf("%s_cgroup_test", subsystem))

	err = os.MkdirAll(testCgroupPath, 0755)
	if err != nil {
		t.Fatal(err)
	}

	return &cgroupTestUtil{CgroupData: d, CgroupPath: testCgroupPath, t: t}
}

func (c *cgroupTestUtil) cleanup() {
	os.RemoveAll(c.CgroupPath)
}

// FIXME: Need to be removed as well as tempCgroupTestUtil when we figure
// out a better way.
func (c *cgroupTestUtil) tempCleanup() {
	os.RemoveAll(c.CgroupData.root)
}

// Write the specified contents on the mock of the specified cgroup files,
// caller should ensure these files are exist.
func (c *cgroupTestUtil) writeFileContents(fileContents map[string]string) {
	for file, contents := range fileContents {
		err := writeFile(c.CgroupPath, file, contents)
		if err != nil {
			c.t.Fatal(err)
		}
	}
}
