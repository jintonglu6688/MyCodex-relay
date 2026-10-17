package session

import "sync"

const (
	ConnectionHost   = "windows_host"
	ConnectionDevice = "mobile_device"
)

type Session struct {
	TenantID       string
	HostID         string
	DeviceID       string
	SessionID      string
	ConnectionType string
}

type Registry struct {
	mu      sync.RWMutex
	hosts   map[string]Session
	devices map[string]Session
}

func NewRegistry() *Registry {
	return &Registry{
		hosts:   make(map[string]Session),
		devices: make(map[string]Session),
	}
}

func (r *Registry) Add(session Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if session.ConnectionType == ConnectionHost {
		r.hosts[hostKey(session.TenantID, session.HostID)] = session
	}
	if session.ConnectionType == ConnectionDevice {
		r.devices[deviceKey(session.TenantID, session.HostID, session.DeviceID)] = session
	}
}

func (r *Registry) FindHost(tenantID string, hostID string) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.hosts[hostKey(tenantID, hostID)]
	return session, ok
}

func (r *Registry) FindDevice(tenantID string, hostID string, deviceID string) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.devices[deviceKey(tenantID, hostID, deviceID)]
	return session, ok
}

func hostKey(tenantID string, hostID string) string {
	return tenantID + "/" + hostID
}

func deviceKey(tenantID string, hostID string, deviceID string) string {
	return tenantID + "/" + hostID + "/" + deviceID
}
