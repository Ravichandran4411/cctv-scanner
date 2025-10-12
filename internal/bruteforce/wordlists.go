package bruteforce

// GetDictionaryPasswords returns password candidates from wordlists
func GetDictionaryPasswords(wordlist string, customPasswords []string) ([]PasswordCandidate, error) {
	candidates := make([]PasswordCandidate, 0)
	usernames := []string{"admin", "root", "user", "administrator", "support", "guest"}

	var passwords []string

	if customPasswords != nil && len(customPasswords) > 0 {
		passwords = customPasswords
	} else {
		switch wordlist {
		case "extended":
			passwords = getExtendedWordlist()
		default:
			passwords = getDefaultWordlist()
		}
	}

	for _, username := range usernames {
		for _, password := range passwords {
			candidates = append(candidates, PasswordCandidate{
				Username: username,
				Password: password,
			})
		}
	}

	return candidates, nil
}

func getDefaultWordlist() []string {
	return []string{
		// Empty/default passwords
		"", "admin", "password", "12345", "123456", "1234", "123",

		// Camera defaults
		"admin123", "Admin123", "admin@123", "password123",
		"default", "camera", "security",

		// Brand specific
		"hikvision", "Hikvision", "hik12345", "ikwd",
		"dahua", "Dahua", "dahua123", "7ujMko0admin",
		"foscam", "Foscam", "foscam123",
		"axis", "root", "pass",

		// Common patterns
		"admin2024", "admin2023", "admin2025",
		"Admin@2024", "password2024", "Password123",
		"admin!", "admin@", "admin#",

		// Years
		"2024", "2023", "2025", "2022", "2021",

		// Simple numbers
		"0000", "1111", "9999", "123456789",
		"111111", "000000",

		// Words
		"welcome", "Welcome", "Welcome123",
		"office", "Office123", "camera123",
	}
}

func getExtendedWordlist() []string {
	base := getDefaultWordlist()
	
	// Add more variations
	extended := []string{
		"supervisor", "service", "tech", "installer",
		"666666", "888888", "654321", "abcd1234",
		"qwerty", "abc123", "password1", "admin1",
		"system", "support123", "master", "operator",
	}

	return append(base, extended...)
}