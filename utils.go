package libcontainer

// getNamespaceFlags parses the container's Namespaces options to set the correct
// flags on clone, unshare, and setns
func getNamespaceFlags(namespaces map[string]bool) (flag int) {
	for key, enabled := range namespaces {
		if enabled {
			if ns := getNamespace(key); ns != nil {
				flag |= ns.Value
			}
		}
	}

	return flag
}
