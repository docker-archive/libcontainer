package mode

import (
	"strings"
)

type Mode struct {
	ModeString string `json:"modestring,omitempty"`
}

func (m *Mode) Writable() bool {
	if strings.Index(strings.ToLower(m.ModeString), "r") != -1 && strings.Index(strings.ToLower(m.ModeString), "w") == -1 {
		return false
	}
	return true
}

func (m *Mode) Relabel() bool {
	return !(strings.Index(m.ModeString, "z") == -1 && strings.Index(m.ModeString, "Z") == -1)
}

func (m *Mode) Shared() bool {
	return strings.Index(m.ModeString, "z") != -1
}

func (m *Mode) Private() bool {
	return strings.Index(m.ModeString, "Z") != -1
}

func (m *Mode) MakeReadOnly() Mode {
	modes := strings.Split(m.ModeString, "w")
	modes = strings.Split(strings.Join(modes, ""), "W")
	return Mode{ModeString: strings.Join(modes, "") + "r"}
}

func ReadOnly() Mode {
	return Mode{ModeString: "r"}
}

func ReadWrite() Mode {
	return Mode{ModeString: "w"}
}

func Nil() Mode {
	return Mode{ModeString: ""}
}

func Init(s string) Mode {
	return Mode{ModeString: s}
}

/*
Valid takes the string and then verifies the option.  Also takes a
flag indicating whether or not the caller supports relabling.  BindMounts
support relabeling, while VolumesFrom do not.
*/
func Valid(m string, relabel bool) bool {
	validModes := map[string]bool{
		"rw": true,
		"ro": true,
		"r":  true,
		"o":  true,
		"w":  true,
		"R":  true,
		"W":  true,
	}
	if relabel {
		validModes["z"] = true
		validModes["Z"] = true
		if strings.Index(m, "z") != -1 && strings.Index(m, "Z") != -1 {
			return false
		}
	}
	for i := 0; i < len(m); i++ {
		if !validModes[string(m[i])] {
			return false
		}
	}
	return true
}
