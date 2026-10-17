package authhttp

import (
	"net/http"
	"net/netip"
	"strings"
)

// Only a directly trusted proxy may supply client metadata. Walk from the
// nearest hop toward the client, stopping at the first untrusted address so
// client-supplied leftmost values cannot bypass limits. The proxy must strip
// or append its verified peer address, not forward arbitrary metadata verbatim.
func (h *Handler) peer(r *http.Request) string {
	direct := peer(r)
	address, err := netip.ParseAddr(direct)
	if err != nil {
		return "unknown"
	}
	trusted := func(ip netip.Addr) bool {
		for _, prefix := range h.trustedProxies {
			if prefix.Contains(ip.Unmap()) {
				return true
			}
		}
		return false
	}
	if !trusted(address) {
		return address.Unmap().String()
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 || len(values[0]) > 1024 {
		return direct
	}
	hops := strings.Split(values[0], ",")
	if len(hops) > 16 {
		return direct
	}
	// Validate the entire chain before using it, including ignored outer hops.
	chain := make([]netip.Addr, len(hops))
	for i, value := range hops {
		ip, e := netip.ParseAddr(strings.TrimSpace(value))
		if e != nil || ip.Zone() != "" {
			return direct
		}
		chain[i] = ip.Unmap()
	}
	for i := len(chain) - 1; i >= 0; i-- {
		address = chain[i]
		if !trusted(address) {
			return address.String()
		}
	}
	return address.String()
}
