package kvstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/metric"
	"github.com/rs/zerolog/log"

	"github.com/luxfi/mpc/pkg/encryption"
)

const (
	magic            = "LUX_MPC_BACKUP"
	dbPath           = "./db"
	defaultBackupDir = "./backups"
)

// BackupMeta holds metadata for an encrypted ZapDB backup file.
type BackupMeta struct {
	Algo            string `json:"algo"`              // AES-256-GCM
	NonceB64        string `json:"nonce_b64"`         // base64 nonce
	CreatedAt       string `json:"created_at"`        // RFC3339
	Since           uint64 `json:"since"`             // input watermark
	NextSince       uint64 `json:"next_since"`        // output watermark
	EncryptionKeyID string `json:"encryption_key_id"` // sha256(key) prefix
}

// BackupVersion tracks the incremental backup state.
type BackupVersion struct {
	Version   uint64 `json:"version"`    // Human-readable counter
	Since     uint64 `json:"since"`      // DB internal backup offset
	UpdatedAt string `json:"updated_at"` // RFC3339
}

// Backup handles encrypted ZapDB backups.
type Backup struct {
	NodeID string
	DB     database.Database
	Key    []byte
	Dir    string
}

// NewBackup creates a new backup executor. If dir is empty, uses ./backups.
func NewBackup(
	nodeID string,
	db database.Database,
	key []byte,
	dir string,
) *Backup {
	if dir == "" {
		dir = defaultBackupDir
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		panic(fmt.Errorf("failed to create backup directory: %w", err))
	}
	return &Backup{
		NodeID: nodeID,
		DB:     db,
		Key:    key,
		Dir:    dir,
	}
}

func (b *Backup) Execute() error {
	info, err := b.LoadVersionInfo()
	if err != nil {
		return fmt.Errorf("failed to load version info: %w", err)
	}

	since := info.Since
	version := info.Version + 1
	now := time.Now()
	filename := fmt.Sprintf("backup-%s-%s-%d.enc", b.NodeID, now.Format("2006-01-02_15-04-05"), version)
	outPath := filepath.Join(b.Dir, filename)

	var plain bytes.Buffer
	nextSince, err := b.DB.Backup(&plain, since)
	if err != nil {
		return err
	}

	if plain.Len() == 0 || nextSince == since {
		fmt.Println("[SKIP] No changes since last backup, skipping.")
		return nil
	}

	// encrypt
	ct, nonce, err := encryption.EncryptAESGCM(plain.Bytes(), b.Key)
	if err != nil {
		return err
	}

	meta := BackupMeta{
		Algo:            "AES-256-GCM",
		NonceB64:        base64.StdEncoding.EncodeToString(nonce),
		CreatedAt:       now.Format(time.RFC3339),
		Since:           since,
		NextSince:       nextSince,
		EncryptionKeyID: fmt.Sprintf("%x", sha256.Sum256(b.Key))[:16],
	}

	metaJSON, _ := json.Marshal(meta)
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write([]byte(magic)); err != nil {
		return err
	}

	metaLen := len(metaJSON)
	if metaLen > math.MaxUint32 {
		return fmt.Errorf("metaJSON too large")
	}

	if err := binary.Write(f, binary.BigEndian, uint32(metaLen)); err != nil {
		return err
	}
	if _, err := f.Write(metaJSON); err != nil {
		return err
	}
	if _, err := f.Write(ct); err != nil {
		return err
	}

	fmt.Println("Encrypted backup successfully:", filename, "next version:", version)
	if err := b.SaveVersionInfo(version, nextSince); err != nil {
		fmt.Println("Warning: Failed to save latest.version:", err)
	}

	return nil
}

func (b *Backup) SaveVersionInfo(counter, since uint64) error {
	info := BackupVersion{
		Version:   counter,
		Since:     since,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	versionFile := filepath.Join(b.Dir, "latest.version")
	return os.WriteFile(versionFile, data, 0600)
}

func (b *Backup) LoadVersionInfo() (BackupVersion, error) {
	var info BackupVersion
	versionFile := filepath.Join(b.Dir, "latest.version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BackupVersion{
				Version:   0,
				Since:     0,
				UpdatedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
		return info, err
	}
	err = json.Unmarshal(data, &info)
	return info, err
}

func (b *Backup) SortedEncryptedBackups() []string {
	files, _ := filepath.Glob(filepath.Join(b.Dir, "backup-*.enc"))
	sort.Strings(files)
	return files
}

// RestoreAllBackupsEncrypted decrypts and loads all backup files into restorePath.
// The restored database is a raw zapdb — values were already individually encrypted
// by the source encdb wrapper, so no additional encryption is applied during restore.
// After restore, open the path with New using the same encryption key to read values correctly.
func (b *Backup) RestoreAllBackupsEncrypted(restorePath string, encryptionKey []byte) error {
	_ = encryptionKey // key validated at open time, not needed for raw load
	err := os.MkdirAll(restorePath, 0700)
	if err != nil {
		return fmt.Errorf("failed to create restore directory: %w", err)
	}

	// Load into a raw zapdb — values in the backup are already encrypted by encdb
	rawDB, err := zapdb.New(restorePath, nil, b.NodeID+"-restore", metric.NewNoOpRegistry())
	if err != nil {
		return err
	}

	for _, file := range b.SortedEncryptedBackups() {
		fmt.Println("Restoring:", file)
		if err := b.loadEncryptedBackup(rawDB, file); err != nil {
			if closeErr := rawDB.Close(); closeErr != nil {
				log.Printf("Failed to close restoreDB: %v", closeErr)
			}
			return err
		}
	}

	if err := rawDB.Close(); err != nil {
		return fmt.Errorf("failed to close restore database: %w", err)
	}
	fmt.Println("Restore complete:", restorePath)
	return nil
}

func (b *Backup) loadEncryptedBackup(db database.Database, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// magic
	magicBuf := make([]byte, len(magic))
	if _, err := io.ReadFull(f, magicBuf); err != nil {
		return err
	}
	if string(magicBuf) != magic {
		return fmt.Errorf("bad magic")
	}

	// meta
	var metaLen uint32
	if err := binary.Read(f, binary.BigEndian, &metaLen); err != nil {
		return err
	}
	metaBuf := make([]byte, metaLen)
	if _, err := io.ReadFull(f, metaBuf); err != nil {
		return err
	}
	var meta BackupMeta
	if err := json.Unmarshal(metaBuf, &meta); err != nil {
		return err
	}
	// ciphertext
	ct, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	nonce, err := base64.StdEncoding.DecodeString(meta.NonceB64)
	if err != nil {
		return err
	}
	plain, err := encryption.DecryptAESGCM(ct, b.Key, nonce)
	if err != nil {
		return err
	}
	return db.Load(bytes.NewReader(plain))
}
