package bruteforce

import (
	"strings"
)

type PasswordCandidate struct {
	Username string
	Password string
}

// GenerateRuleBasedPasswords generates passwords using rules
func GenerateRuleBasedPasswords(targetIP, wordlist string) ([]PasswordCandidate, error) {
	baseWords := GetBaseWords(wordlist)
	candidates := make([]PasswordCandidate, 0)

	// Common usernames
	usernames := []string{"admin", "root", "user", "administrator", "support"}

	for _, username := range usernames {
		for _, word := range baseWords {
			// Apply transformation rules
			variations := applyRules(word)
			
			for _, password := range variations {
				candidates = append(candidates, PasswordCandidate{
					Username: username,
					Password: password,
				})
			}
		}
	}

	return candidates, nil
}

// GenerateHybridPasswords combines dictionary + rules
func GenerateHybridPasswords(targetIP, wordlist string) ([]PasswordCandidate, error) {
	dictPasswords, _ := GetDictionaryPasswords(wordlist, nil)
	rulePasswords, _ := GenerateRuleBasedPasswords(targetIP, wordlist)

	// Combine and deduplicate
	seen := make(map[string]bool)
	result := make([]PasswordCandidate, 0)

	for _, p := range append(dictPasswords, rulePasswords...) {
		key := p.Username + ":" + p.Password
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}

	return result, nil
}

// applyRules applies transformation rules to a base word
func applyRules(word string) []string {
	variations := []string{word}

	// Rule 1: Capitalization
	variations = append(variations, capitalize(word))
	variations = append(variations, strings.ToUpper(word))

	// Rule 2: Append years
	years := []string{"2024", "2023", "2025", "2022", "123"}
	for _, year := range years {
		variations = append(variations, word+year)
		variations = append(variations, capitalize(word)+year)
	}

	// Rule 3: Special characters
	specials := []string{"!", "@", "#", "$", "123", "@123", "!123"}
	for _, special := range specials {
		variations = append(variations, word+special)
		variations = append(variations, capitalize(word)+special)
	}

	// Rule 4: Leetspeak
	variations = append(variations, toLeetspeak(word))

	// Rule 5: Combinations
	variations = append(variations, word+"@2024")
	variations = append(variations, capitalize(word)+"@123")
	variations = append(variations, capitalize(word)+"!2024")

	return variations
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func toLeetspeak(s string) string {
	replacements := map[string]string{
		"a": "4", "A": "4",
		"e": "3", "E": "3",
		"i": "1", "I": "1",
		"o": "0", "O": "0",
		"s": "5", "S": "5",
		"t": "7", "T": "7",
	}

	result := s
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}
	return result
}

func GetBaseWords(wordlist string) []string {
	// Base words for rule generation
	return []string{
		"admin", "password", "camera", "default",
		"root", "user", "support", "guest",
		"hikvision", "dahua", "axis", "foscam",
		"12345", "123456", "1234", "office",
	}
}