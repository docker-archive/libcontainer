package validate

import (
	"testing"

	"github.com/docker/libcontainer/configs"
)

func TestProcMount(t *testing.T) {
	v := &ConfigValidator{}

	config := &configs.Config{
		Namespaces: configs.Namespaces{{Type: configs.NEWPID}},
	}
	err := v.procMount(config)
	if err != nil {
		t.Fatalf("procMount failed to check proc mount")
	}

	config = &configs.Config{
		Namespaces: configs.Namespaces{{Type: configs.NEWNS}},
	}
	err = v.procMount(config)
	if err == nil {
		t.Fatalf("procMount failed to check proc mount")
	}

	config = &configs.Config{
		Namespaces: configs.Namespaces{{Type: configs.NEWNS}},
		Mounts: []*configs.Mount{
			{Source: "proc",
				Destination: "/proc",
			},
		},
	}
	err = v.procMount(config)
	if err != nil {
		t.Fatalf("procMount failed to check proc mount")
	}
}
