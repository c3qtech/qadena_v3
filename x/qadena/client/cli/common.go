package cli

import (
	"sort"
)

func findSenderOption(senderOptions []string, option string) bool {
	if sort.SearchStrings(senderOptions, option) == len(senderOptions) {
		return false
	}
	return true
}
