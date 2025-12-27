package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SafePath validates and constructs a safe file path within a base directory.
// Returns an error if the resulting path would escape the base directory.
func SafePath(baseDir, filename string) (string, error) {
	// Reject absolute paths in filename
	if filepath.IsAbs(filename) {
		return "", fmt.Errorf("invalid filename: absolute paths not allowed")
	}

	// Reject any path containing ".." before cleaning (catches obvious attacks)
	if strings.Contains(filename, "..") {
		return "", fmt.Errorf("invalid filename: path traversal not allowed")
	}

	// Clean the filename
	cleanFilename := filepath.Clean(filename)

	// After cleaning, reject if ".." appears (handles edge cases)
	if strings.Contains(cleanFilename, "..") {
		return "", fmt.Errorf("invalid filename: path traversal not allowed")
	}

	// Get absolute base directory path
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for base directory: %w", err)
	}

	// Construct and resolve the full path
	fullPath := filepath.Join(absBase, cleanFilename)

	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Ensure the resolved path is within the base directory
	// Add trailing separator to absBase to prevent prefix matching issues
	// (e.g., /foo/bar matching /foo/barbaz)
	basePrefixCheck := absBase
	if !strings.HasSuffix(basePrefixCheck, string(filepath.Separator)) {
		basePrefixCheck += string(filepath.Separator)
	}

	// The path is safe if it equals absBase or starts with absBase + separator
	if absPath != absBase && !strings.HasPrefix(absPath, basePrefixCheck) {
		return "", fmt.Errorf("path outside base directory not allowed")
	}

	return fullPath, nil
}

// ValidateFilePath validates a file path for security concerns
func ValidateFilePath(filePath string) error {
	// Clean the path
	cleanPath := filepath.Clean(filePath)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid file path: path traversal not allowed")
	}

	return nil
}
