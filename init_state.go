package libcontainer

// initState is an internal struct for serializing and sending the container's
// configuration, state, and process information to child processes
type initState struct {
	Process *Process `json:"process,omitempty"`
	Config  *Config  `json:"config,omitempty"`
	State   *State   `json:"state,omitempty"`
}
