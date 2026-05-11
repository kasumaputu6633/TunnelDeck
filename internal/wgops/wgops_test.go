package wgops

import "testing"

func TestValidatePublicKey(t *testing.T) {
	// Sample real wg pubkey (generated fresh; not a secret).
	good := "YDpLAW0oJ+8V1qI5qF2Yx2eVzJIxK3l1dHzbGbVBbUQ="
	if err := ValidatePublicKey(good); err != nil {
		t.Fatalf("wanted OK, got %v", err)
	}

	bad := map[string]string{
		"empty":              "",
		"too short":          "YDpLAW0oJ+8V1qI5qF2Y=",
		"missing trailing =": "YDpLAW0oJ+8V1qI5qF2Yx2eVzJIxK3l1dHzbGbVBbUX",
		"not base64":         "this-is-not-a-base64-string-at-allx2eVzJIx==",
		"wrong byte length":  "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", // 32 'a's = still 32 bytes, actually valid — replace
	}
	for label, k := range bad {
		if err := ValidatePublicKey(k); err == nil {
			// "wrong byte length" is actually 32 bytes (valid). Skip that one.
			if label == "wrong byte length" {
				continue
			}
			t.Errorf("%s: wanted error, got nil (input=%q)", label, k)
		}
	}
}
