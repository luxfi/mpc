package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
)

// S3Config configures S3-compatible backup storage
type S3Config struct {
	Endpoint  string // e.g., "s3.amazonaws.com" or "minio.example.com"
	Bucket    string // e.g., "lux-mpc-backups"
	AccessKey string
	SecretKey string
	Region    string // e.g., "us-east-1"
	UseSSL    bool
	Prefix    string // e.g., "mpc/node0/"
}

// S3ConfigFromEnv creates S3Config from environment variables
func S3ConfigFromEnv(nodeID string) *S3Config {
	endpoint := os.Getenv("S3_ENDPOINT")
	if endpoint == "" {
		return nil // S3 not configured
	}

	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		bucket = "lux-mpc-backups"
	}

	prefix := os.Getenv("S3_PREFIX")
	if prefix == "" {
		prefix = fmt.Sprintf("mpc/%s/", nodeID)
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	useSSL := os.Getenv("S3_USE_SSL") != "false"

	return &S3Config{
		Endpoint:  endpoint,
		Bucket:    bucket,
		AccessKey: os.Getenv("S3_ACCESS_KEY"),
		SecretKey: os.Getenv("S3_SECRET_KEY"),
		Region:    os.Getenv("S3_REGION"),
		UseSSL:    useSSL,
		Prefix:    prefix,
	}
}

// Manager handles periodic backups with optional S3 upload
type Manager struct {
	executor *kvstore.BadgerBackupExecutor
	backupDir string
	s3Config *S3Config
	s3Client *minio.Client
	nodeID   string
	period   time.Duration
	done     chan struct{}
}

// NewManager creates a backup manager
func NewManager(executor *kvstore.BadgerBackupExecutor, backupDir, nodeID string, period time.Duration, s3Cfg *S3Config) (*Manager, error) {
	m := &Manager{
		executor:  executor,
		backupDir: backupDir,
		s3Config:  s3Cfg,
		nodeID:    nodeID,
		period:    period,
		done:      make(chan struct{}),
	}

	if s3Cfg != nil && s3Cfg.Endpoint != "" {
		client, err := minio.New(s3Cfg.Endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(s3Cfg.AccessKey, s3Cfg.SecretKey, ""),
			Secure: s3Cfg.UseSSL,
			Region: s3Cfg.Region,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create S3 client: %w", err)
		}
		m.s3Client = client

		// Ensure bucket exists
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		exists, err := client.BucketExists(ctx, s3Cfg.Bucket)
		if err != nil {
			logger.Warn("Failed to check S3 bucket", "bucket", s3Cfg.Bucket, "err", err)
		} else if !exists {
			if err := client.MakeBucket(ctx, s3Cfg.Bucket, minio.MakeBucketOptions{Region: s3Cfg.Region}); err != nil {
				logger.Warn("Failed to create S3 bucket", "bucket", s3Cfg.Bucket, "err", err)
			} else {
				logger.Info("Created S3 bucket", "bucket", s3Cfg.Bucket)
			}
		}

		logger.Info("S3 backup enabled",
			"endpoint", s3Cfg.Endpoint,
			"bucket", s3Cfg.Bucket,
			"prefix", s3Cfg.Prefix,
		)
	}

	return m, nil
}

// Start begins the periodic backup loop
func (m *Manager) Start() {
	go m.loop()
}

// Stop stops the backup manager
func (m *Manager) Stop() {
	close(m.done)
}

func (m *Manager) loop() {
	ticker := time.NewTicker(m.period)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			if err := m.RunBackup(); err != nil {
				logger.Error("Backup failed", err)
			}
		}
	}
}

// RunBackup executes a backup and uploads to S3 if configured
func (m *Manager) RunBackup() error {
	// Get list of files before backup
	beforeFiles := m.executor.SortedEncryptedBackups()

	// Execute local backup
	if err := m.executor.Execute(); err != nil {
		return fmt.Errorf("local backup failed: %w", err)
	}

	// Find new files
	afterFiles := m.executor.SortedEncryptedBackups()
	newFiles := findNewFiles(beforeFiles, afterFiles)

	if len(newFiles) == 0 {
		return nil // No new backup (no changes)
	}

	// Upload new files to S3
	if m.s3Client != nil {
		for _, f := range newFiles {
			if err := m.uploadToS3(f); err != nil {
				logger.Error("S3 upload failed", err, "file", f)
				// Don't return error - local backup succeeded
			}
		}
	}

	return nil
}

func (m *Manager) uploadToS3(localPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	filename := filepath.Base(localPath)
	objectName := m.s3Config.Prefix + filename

	info, err := m.s3Client.FPutObject(ctx, m.s3Config.Bucket, objectName, localPath, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("S3 upload failed: %w", err)
	}

	logger.Info("Backup uploaded to S3",
		"file", filename,
		"bucket", m.s3Config.Bucket,
		"object", objectName,
		"size", info.Size,
	)
	return nil
}

func findNewFiles(before, after []string) []string {
	existing := make(map[string]bool, len(before))
	for _, f := range before {
		existing[f] = true
	}
	var newFiles []string
	for _, f := range after {
		if !existing[f] {
			newFiles = append(newFiles, f)
		}
	}
	return newFiles
}
