// Program ci builds and runs unit tests for the package in CI.
//
// Because the Security framework requires MacOS entitlements,
// you cannot simply run 'go test ./...'. Doing so will
// result in errors such as
//
//		--- FAIL: TestGenericPassword_Add (0.00s)
//	   		--- FAIL: TestGenericPassword_Add/ok (0.00s)
//	       		generic_password_test.go:33: GenericPassword.Add() error = keychain error (-34018), wantErr false
//
// Instead, we must compile a binary containing the tests and codesign it
// with entitlements allowing us to access the keychain.
//
// Usage: from the root of the repo, run
//
//	go run cmd/ci/main.go
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"text/template"
)

func main() {
	// debug := os.Getenv("DEBUG") == "true"

	// cfg, err := readCodesignConfig()
	// if err != nil {
	// 	log.Fatalf("failed to read codesign config: %v", err)
	// }

	// delete the 'bin' folder if it exists
	if _, err := os.Stat("bin"); err == nil {
		if err := os.RemoveAll("bin"); err != nil {
			log.Fatalf("failed to delete 'bin' directory: %v", err)
		}
	}

	if err := os.Mkdir("bin", 0755); err != nil {
		log.Fatalf("failed to create 'bin' directory: %v", err)
	}

	// compile a binary for the tests.
	fmt.Println("compiling test binaries...")
	cmd := exec.Command("go", "test", "-o", "bin", "-c", "./...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to compile tests: %v", err)
	}

	fmt.Println("packaging test binaries...")
	cmd = exec.Command("pkgbuild", "--identifier", "goapplesecurity.test", "--install-location", "/usr/local/bin/goapplesecurity", "--root", "./bin", "tests.pkg")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to package test binaries: %v", err)
	}

	// files, err := os.ReadDir("bin")
	// if err != nil {
	// 	log.Fatalf("failed to read 'bin' directory: %v", err)
	// }

	// // create a temporary directory and defer its deletion
	// tmpDir, err := os.MkdirTemp("", "go-apple-security-testing*")
	// if err != nil {
	// 	log.Fatalf("failed to create temporary directory: %v", err)
	// }
	// defer os.RemoveAll(tmpDir)

	// for _, file := range files {
	// 	if file.IsDir() {
	// 		continue
	// 	}
	// 	entitlements := cfg.Entitlements(file.Name())
	// 	entitlementsPath := filepath.Join(tmpDir, file.Name()+"-entitlements")
	// 	os.WriteFile(entitlementsPath, []byte(entitlements), 0755)

	// 	if debug {
	// 		fmt.Printf("wrote entitlements to %q:\n%s\n", entitlementsPath, entitlements)
	// 	}

	// 	binaryPath := fmt.Sprintf("bin/%s", file.Name())
	// 	fmt.Printf("codesigning %q with identity %q...\n", binaryPath, cfg.Identity)
	// 	cmd = exec.Command("codesign", "-s", cfg.Identity, "--entitlements", entitlementsPath, binaryPath)
	// 	cmd.Stdout = os.Stdout
	// 	cmd.Stderr = os.Stderr
	// 	if err := cmd.Run(); err != nil {
	// 		log.Fatalf("failed to codesign '%s': %v", binaryPath, err)
	// 	}

	// 	if debug {
	// 		fmt.Printf("checking entitlements on %q...\n", binaryPath)
	// 		cmd = exec.Command("codesign", "-d", "--entitlements", "-", "--xml", binaryPath)
	// 		cmd.Stdout = os.Stdout
	// 		cmd.Stderr = os.Stderr
	// 		if err := cmd.Run(); err != nil {
	// 			log.Fatalf("failed to check entitlements for '%s': %v", binaryPath, err)
	// 		}

	// 		fmt.Printf("checking code signature on %q...\n", binaryPath)
	// 		cmd = exec.Command("codesign", "-vvv", binaryPath)
	// 		cmd.Stdout = os.Stdout
	// 		cmd.Stderr = os.Stderr
	// 		if err := cmd.Run(); err != nil {
	// 			log.Fatalf("failed to check code signature for '%s': %v", binaryPath, err)
	// 		}

	// 		fmt.Printf("checking SecAssessment system policy security on %q...\n", binaryPath)
	// 		cmd = exec.Command("spctl", "--assess", "--verbose", binaryPath)
	// 		cmd.Stdout = os.Stdout
	// 		cmd.Stderr = os.Stderr
	// 		if err := cmd.Run(); err != nil {
	// 			log.Fatalf("failed to check SecAssessment for '%s': %v", binaryPath, err)
	// 		}
	// 	}

	// 	if os.Getenv("CI") == "true" && file.Name() == "enclavekey.test" {
	// 		fmt.Printf("skipping running %q as it is not supported on GitHub Actions...\n", binaryPath)
	// 		continue
	// 	}

	// 	fmt.Printf("running %q...\n", binaryPath)
	// 	cmd = exec.Command(binaryPath, "-test.v")
	// 	cmd.Stdout = os.Stdout
	// 	cmd.Stderr = os.Stderr
	// 	if err := cmd.Run(); err != nil {
	// 		log.Fatalf("failed to run %q: %v", binaryPath, err)
	// 	}
	// }
}

func readCodesignConfig() (*codesignConfig, error) {

	// running in CI, so require env vars to be set
	var cfg codesignConfig
	cfg.Identity = os.Getenv("CODESIGN_IDENTITY")
	cfg.TeamID = os.Getenv("CODESIGN_TEAM_ID")

	if cfg.Identity == "" {
		return nil, errors.New("CODESIGN_IDENTITY must be set")
	}
	if cfg.TeamID == "" {
		return nil, errors.New("CODESIGN_TEAM_ID must be set")
	}

	return &cfg, nil
}

type codesignConfig struct {
	Identity string `json:"identity"`
	TeamID   string `json:"team_id"`
}

func (c codesignConfig) Entitlements(binary string) string {
	tpl := `<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
		<key>com.apple.application-identifier</key>
		<string>{{ .TeamID }}.goapplesecurity.test.{{ .Binary }}</string>
		<key>com.apple.developer.team-identifier</key>
		<string>{{ .TeamID }}</string>
		<key>keychain-access-groups</key>
		<array>
			<string>{{ .TeamID }}.goapplesecurity.test.shared</string>
		</array>
	</dict>
	</plist>
	`
	tmpl, err := template.New("entitlements").Parse(tpl)
	if err != nil {
		log.Fatalf("failed to parse entitlements template: %v", err)
	}

	data := struct {
		Identity            string
		TeamID              string
		AppPrefix           string
		Binary              string
		KeychainAccessGroup string
	}{
		Identity: c.Identity,
		TeamID:   c.TeamID,
		Binary:   binary,
	}

	var entitlements bytes.Buffer
	if err := tmpl.Execute(&entitlements, data); err != nil {
		log.Fatalf("failed to execute entitlements template: %v", err)
	}

	return entitlements.String()
}
