package custody

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DeviceStore persists device registrations. Implementations must be safe
// for concurrent use. All queries are scoped by walletID for tenant isolation.
type DeviceStore interface {
	// RegisterDevice enrolls a new device for a wallet. Returns an error if
	// the device is already registered for this wallet.
	RegisterDevice(ctx context.Context, reg DeviceRegistration) error

	// GetDevice retrieves a single device by wallet and device ID.
	GetDevice(ctx context.Context, walletID, deviceID string) (*DeviceRegistration, error)

	// ListDevices returns all devices enrolled for a wallet.
	ListDevices(ctx context.Context, walletID string) ([]DeviceRegistration, error)

	// UpdateLastUsed records the timestamp of the most recent biometric signing.
	UpdateLastUsed(ctx context.Context, walletID, deviceID string) error

	// RevokeDevice removes a device enrollment. After revocation, the device
	// can no longer participate in MPC signing for this wallet.
	RevokeDevice(ctx context.Context, walletID, deviceID string) error
}

// MemoryDeviceStore is an in-memory DeviceStore for development and testing.
// NOT FOR PRODUCTION -- use the ORM-backed store via the API server.
type MemoryDeviceStore struct {
	mu      sync.RWMutex
	devices map[string]map[string]DeviceRegistration // walletID -> deviceID -> reg
}

// NewMemoryDeviceStore creates an empty in-memory device store.
func NewMemoryDeviceStore() *MemoryDeviceStore {
	return &MemoryDeviceStore{
		devices: make(map[string]map[string]DeviceRegistration),
	}
}

func (m *MemoryDeviceStore) RegisterDevice(_ context.Context, reg DeviceRegistration) error {
	if reg.WalletID == "" || reg.DeviceID == "" {
		return errors.New("wallet_id and device_id are required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	byWallet, ok := m.devices[reg.WalletID]
	if !ok {
		byWallet = make(map[string]DeviceRegistration)
		m.devices[reg.WalletID] = byWallet
	}
	if _, exists := byWallet[reg.DeviceID]; exists {
		return errors.New("device already registered for this wallet")
	}

	reg.EnrolledAt = time.Now()
	reg.LastUsed = reg.EnrolledAt
	byWallet[reg.DeviceID] = reg
	return nil
}

func (m *MemoryDeviceStore) GetDevice(_ context.Context, walletID, deviceID string) (*DeviceRegistration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	byWallet, ok := m.devices[walletID]
	if !ok {
		return nil, errors.New("no devices registered for wallet")
	}
	reg, ok := byWallet[deviceID]
	if !ok {
		return nil, errors.New("device not found")
	}
	return &reg, nil
}

func (m *MemoryDeviceStore) ListDevices(_ context.Context, walletID string) ([]DeviceRegistration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	byWallet, ok := m.devices[walletID]
	if !ok {
		return []DeviceRegistration{}, nil
	}

	result := make([]DeviceRegistration, 0, len(byWallet))
	for _, reg := range byWallet {
		result = append(result, reg)
	}
	return result, nil
}

func (m *MemoryDeviceStore) UpdateLastUsed(_ context.Context, walletID, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	byWallet, ok := m.devices[walletID]
	if !ok {
		return errors.New("no devices registered for wallet")
	}
	reg, ok := byWallet[deviceID]
	if !ok {
		return errors.New("device not found")
	}
	reg.LastUsed = time.Now()
	byWallet[deviceID] = reg
	return nil
}

func (m *MemoryDeviceStore) RevokeDevice(_ context.Context, walletID, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	byWallet, ok := m.devices[walletID]
	if !ok {
		return errors.New("no devices registered for wallet")
	}
	if _, ok := byWallet[deviceID]; !ok {
		return errors.New("device not found")
	}
	delete(byWallet, deviceID)
	return nil
}
