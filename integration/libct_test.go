// +build libct

package integration

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/cgroups/systemd"
	"testing"
)

func libctRun(m *testing.M) int {
	var err error

	factory, err = libcontainer.NewLibctFactory(".", false)
	if err != nil {
		logrus.Error(err)
		os.Exit(1)
	}

	if systemd.UseSystemd() {
		systemdFactory, err = libcontainer.NewLibctFactory(".", false)
		if err != nil {
			logrus.Error(err)
			os.Exit(1)
		}
	}

	libct = true
	defer func() {
		libct = false
	}()
	return m.Run()
}
