package mode

import (
	"testing"
)

func TestWritable(t *testing.T) {
	m := Init("rwZ")
	if !m.Writable() {
		t.Fatal("Writable option not writable")
	}
	m = Init("W")
	if !m.Writable() {
		t.Fatal("Writable option not writable")
	}
	m = Init("")
	if !m.Writable() {
		t.Fatal("Writable option not writable")
	}

	m = Init("r")
	if m.Writable() {
		t.Fatal("Non Writable option writable")
	}
	m = Init("RW")
	m = m.MakeReadOnly()
	if m.Writable() {
		t.Fatal("Non Writable option writable")
	}
}

func TestRelabel(t *testing.T) {
	m := Init("rwZ")
	if !m.Relabel() {
		t.Fatal("Relabel option not relabel")
	}
	m = Init("rwz")
	if !m.Relabel() {
		t.Fatal("Relabel option not relabel")
	}
	m = Init("W")
	if m.Relabel() {
		t.Fatal("Non Relabel option relabel")
	}
	m = Init("Z")
	if m.Shared() {
		t.Fatal("Private option shared")
	}
	if !m.Private() {
		t.Fatal("Private option shared")
	}

	m = Init("z")
	if !m.Shared() {
		t.Fatal("Shared option not shared")
	}
	if m.Private() {
		t.Fatal("Shared option private")
	}

	m = Init("r")
	if m.Shared() {
		t.Fatal("Non Shared option shared")
	}
	if m.Private() {
		t.Fatal("Non private option private")
	}
}

func TestValid(t *testing.T) {
	valid_ro_opts := []string{
		"ro",
		"roZ",
		"rZ",
	}

	valid_rw_opts := []string{
		"",
		"rw",
		"rwZ",
		"zrw",
		"z",
		"Z",
		"wZ",
	}

	invalid_opts := []string{
		"xyz",
		"zZ",
	}

	for _, opt := range valid_rw_opts {
		if !Valid(opt, true) {
			t.Fatal("Valid option not valid", opt)
			continue
		}
		m := Init(opt)
		if !m.Writable() {
			t.Fatal("Writable option not writable")
		}
	}
	for _, opt := range valid_ro_opts {
		if !Valid(opt, true) {
			t.Fatal("Valid option not valid", opt)
			continue
		}
		m := Init(opt)
		if m.Writable() {
			t.Fatal("Read/Only option writable")
		}
	}
	for _, opt := range invalid_opts {
		if Valid(opt, true) {
			t.Fatal("Not valid option valid", opt)
			continue
		}
	}
}
