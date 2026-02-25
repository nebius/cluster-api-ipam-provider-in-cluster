/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package poolutil implements utility functions to manage pools of IP addresses and network prefixes.
package poolutil

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"sort"
	"strings"

	"go4.org/netipx"
	ipamv1 "sigs.k8s.io/cluster-api/api/ipam/v1beta2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/cluster-api-ipam-provider-in-cluster/api/v1alpha2"
	"sigs.k8s.io/cluster-api-ipam-provider-in-cluster/internal/index"
)

const (
	DefaultAllocationPrefixLength = 64
)

// EffectiveAllocationPrefixLength returns the configured allocation prefix length
// or the default value when the field is not explicitly set.
func EffectiveAllocationPrefixLength(allocationPrefixLength int) int {
	if allocationPrefixLength == 0 {
		return DefaultAllocationPrefixLength
	}
	return allocationPrefixLength
}

// PrefixPoolConfig contains input configuration for prefix allocation.
type PrefixPoolConfig struct {
	Prefixes               []string
	AllocationPrefixLength int
	Gateway                string
	ExcludedPrefixes       []string
}

// NewPrefixPoolConfig builds a PrefixPoolConfig from a pool spec.
func NewPrefixPoolConfig(spec *v1alpha2.InClusterPrefixPoolSpec) *PrefixPoolConfig {
	return &PrefixPoolConfig{
		Prefixes:               spec.Prefixes,
		AllocationPrefixLength: EffectiveAllocationPrefixLength(spec.AllocationPrefixLength),
		Gateway:                spec.Gateway,
		ExcludedPrefixes:       spec.ExcludedPrefixes,
	}
}

// AddressesOutOfRangeIPSet returns an IPSet of the inUseAddresses IPs that are
// not in the poolIPSet.
func AddressesOutOfRangeIPSet(inUseAddresses []ipamv1.IPAddress, poolIPSet *netipx.IPSet) (*netipx.IPSet, error) {
	outOfRangeBuilder := &netipx.IPSetBuilder{}
	for _, address := range inUseAddresses {
		ip, err := netip.ParseAddr(address.Spec.Address)
		if err != nil {
			// if an address we fetch for the pool is unparsable then it isn't in the pool ranges
			continue
		}
		outOfRangeBuilder.Add(ip)
	}
	outOfRangeBuilder.RemoveSet(poolIPSet)
	return outOfRangeBuilder.IPSet()
}

// ListAddressesInUse fetches all IPAddresses belonging to the specified pool.
// Note: requires `index.ipAddressByCombinedPoolRef` to be set up.
func ListAddressesInUse(ctx context.Context, c client.Reader, namespace string, poolRef ipamv1.IPPoolReference) ([]ipamv1.IPAddress, error) {
	addresses := &ipamv1.IPAddressList{}
	err := c.List(ctx, addresses,
		client.MatchingFields{
			index.IPAddressPoolRefCombinedField: index.IPPoolRefValue(poolRef),
		},
		client.InNamespace(namespace),
	)
	if err != nil {
		return nil, err
	}
	return addresses.Items, nil
}

// AddressByNamespacedName finds a specific ip address by namespace and name in a slice of addresses.
func AddressByNamespacedName(addresses []ipamv1.IPAddress, namespace, name string) *ipamv1.IPAddress {
	for _, a := range addresses {
		if a.Namespace == namespace && a.Name == name {
			return &a
		}
	}
	return nil
}

// FindFreeAddress returns the next free IP Address in a range based on a set of existing addresses.
func FindFreeAddress(poolIPSet *netipx.IPSet, inUseIPSet *netipx.IPSet) (netip.Addr, error) {
	for _, iprange := range poolIPSet.Ranges() {
		ip := iprange.From()
		for {
			if !inUseIPSet.Contains(ip) {
				return ip, nil
			}
			if ip == iprange.To() {
				break
			}
			ip = ip.Next()
		}
	}
	return netip.Addr{}, errors.New("no address available")
}

// PoolSpecToIPSet converts a pool spec to an IPSet. Reserved addresses will be
// omitted from the set depending on whether the
// `spec.AllocateReservedIPAddresses` flag is set.
func PoolSpecToIPSet(poolSpec *v1alpha2.InClusterIPPoolSpec) (*netipx.IPSet, error) {
	addressesIPSet, err := AddressesToIPSet(poolSpec.Addresses)
	if err != nil {
		return nil, err // should not happen, webhook validates pools for correctness.
	}

	builder := &netipx.IPSetBuilder{}
	builder.AddSet(addressesIPSet)

	if len(poolSpec.ExcludedAddresses) > 0 {
		excludedAddressesIPSet, err := AddressesToIPSet(poolSpec.ExcludedAddresses)
		if err != nil {
			return nil, err
		}

		builder.RemoveSet(excludedAddressesIPSet)
	}

	if !poolSpec.AllocateReservedIPAddresses {
		subnet := netip.PrefixFrom(addressesIPSet.Ranges()[0].From(), poolSpec.Prefix) // safe because of webhook validation
		subnetRange := netipx.RangeOfPrefix(subnet)
		builder.Remove(subnetRange.From()) // network addr in IPv4, anycast addr in IPv6
		if subnet.Addr().Is4() {
			builder.Remove(subnetRange.To()) // broadcast addr
		}
	}

	if poolSpec.Gateway != "" {
		gateway, err := netip.ParseAddr(poolSpec.Gateway)
		if err != nil {
			return nil, err // should not happen, webhook validates pools for correctness.
		}
		builder.Remove(gateway)
	}

	return builder.IPSet()
}

// AddressesToIPSet converts an array of addresses to an AddressesToIPSet
// addresses may be specified as individual IPs, CIDR ranges, or hyphenated IP
// ranges.
func AddressesToIPSet(addresses []string) (*netipx.IPSet, error) {
	builder := &netipx.IPSetBuilder{}
	for _, addressStr := range addresses {
		ipSet, err := AddressToIPSet(addressStr)
		if err != nil {
			return nil, err
		}
		builder.AddSet(ipSet)
	}
	return builder.IPSet()
}

// AddressToIPSet converts an addresses to an AddressesToIPSet addresses may be
// specified as individual IPs, CIDR ranges, or hyphenated IP ranges.
func AddressToIPSet(addressStr string) (*netipx.IPSet, error) {
	builder := &netipx.IPSetBuilder{}

	if strings.Contains(addressStr, "-") {
		addrRange, err := netipx.ParseIPRange(addressStr)
		if err != nil {
			return nil, err
		}
		builder.AddRange(addrRange)
	} else if strings.Contains(addressStr, "/") {
		prefix, err := netip.ParsePrefix(addressStr)
		if err != nil {
			return nil, err
		}
		builder.AddPrefix(prefix)
	} else {
		addr, err := netip.ParseAddr(addressStr)
		if err != nil {
			return nil, err
		}
		builder.Add(addr)
	}

	return builder.IPSet()
}

// IPSetCount returns the number of IPs contained in the given IPSet.
// This function returns type int, which is much smaller than
// the possible size of a range, which could be 2^128 IPs.
// When an IPSet's count is would be larger than an int, math.MaxInt
// is returned instead.
func IPSetCount(ipSet *netipx.IPSet) int {
	if ipSet == nil {
		return 0
	}

	total := big.NewInt(0)
	for _, iprange := range ipSet.Ranges() {
		total.Add(
			total,
			big.NewInt(0).Sub(
				big.NewInt(0).SetBytes(iprange.To().AsSlice()),
				big.NewInt(0).SetBytes(iprange.From().AsSlice()),
			),
		)
		// Subtracting To and From misses that one of those is a valid IP
		total.Add(total, big.NewInt(1))
	}

	// If total is greater than Uint64, Uint64() will return 0
	// We want to display MaxInt if the value overflows what int can contain
	if total.IsInt64() && total.Uint64() <= uint64(math.MaxInt) {
		return int(total.Uint64()) //nolint:gosec // [G115] conversion is safe with check beforehand
	}
	return math.MaxInt
}

// AddressStrParses checks to see that the addresss string is one of
// a valid single IP address, a hyphonated IP range, or a Prefix.
func AddressStrParses(addressStr string) bool {
	_, err := AddressToIPSet(addressStr)
	return err == nil
}

// FindFreePrefix returns the next free prefix based on pool config and existing allocations.
func FindFreePrefix(poolConfig *PrefixPoolConfig, inUseIPSet *netipx.IPSet) (netip.Prefix, error) {
	allocLen, err := validatedAllocationPrefixLength(poolConfig)
	if err != nil {
		return netip.Prefix{}, err
	}

	poolIPSet, err := PrefixesToIPSet(poolConfig.Prefixes)
	if err != nil {
		return netip.Prefix{}, err
	}

	blockedIPSet, err := prefixPoolBlockedIPSet(poolConfig, inUseIPSet)
	if err != nil {
		return netip.Prefix{}, err
	}

	for _, aggregate := range sortedPrefixes(poolIPSet.Prefixes()) {
		if freePrefix, ok := findFreePrefixInAggregate(aggregate, allocLen, blockedIPSet); ok {
			return freePrefix, nil
		}
	}

	return netip.Prefix{}, errors.New("no prefix available")
}

// PrefixCandidateCount returns the count of allocatable prefixes from the pool configuration.
func PrefixCandidateCount(poolConfig *PrefixPoolConfig) (int, error) {
	allocLen, err := validatedAllocationPrefixLength(poolConfig)
	if err != nil {
		return 0, err
	}

	poolIPSet, err := PrefixesToIPSet(poolConfig.Prefixes)
	if err != nil {
		return 0, err
	}

	blockedIPSet, err := prefixPoolBlockedIPSet(poolConfig, nil)
	if err != nil {
		return 0, err
	}

	total := 0
	for _, aggregate := range sortedPrefixes(poolIPSet.Prefixes()) {
		total = addIntCapped(total, countAllocatablePrefixesInAggregate(aggregate, allocLen, blockedIPSet))
	}
	return total, nil
}

// PrefixIsAllocatable returns true if a prefix is allocatable for the given pool configuration.
func PrefixIsAllocatable(prefix netip.Prefix, poolConfig *PrefixPoolConfig) bool {
	if poolConfig == nil || !prefix.IsValid() {
		return false
	}
	allocLen, err := validatedAllocationPrefixLength(poolConfig)
	if err != nil {
		return false
	}

	prefix = prefix.Masked()
	if prefix.Bits() != allocLen {
		return false
	}

	poolIPSet, err := PrefixesToIPSet(poolConfig.Prefixes)
	if err != nil {
		return false
	}

	if !poolIPSet.ContainsPrefix(prefix) {
		return false
	}

	blockedIPSet, err := prefixPoolBlockedIPSet(poolConfig, nil)
	if err != nil {
		return false
	}

	return !blockedIPSet.OverlapsPrefix(prefix)
}

func validatedAllocationPrefixLength(poolConfig *PrefixPoolConfig) (int, error) {
	if poolConfig == nil {
		return 0, errors.New("prefix pool config is required")
	}
	if poolConfig.AllocationPrefixLength <= 0 || poolConfig.AllocationPrefixLength > 128 {
		return 0, fmt.Errorf("invalid prefix length %d", poolConfig.AllocationPrefixLength)
	}
	return poolConfig.AllocationPrefixLength, nil
}

// PrefixFromIPAddress derives an allocation prefix from an IPAddress resource.
func PrefixFromIPAddress(address ipamv1.IPAddress) (netip.Prefix, error) {
	if address.Spec.Prefix == nil {
		return netip.Prefix{}, fmt.Errorf("address %s/%s has no prefix set", address.Namespace, address.Name)
	}

	prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", address.Spec.Address, *address.Spec.Prefix))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed parsing address %s/%s as prefix: %w", address.Namespace, address.Name, err)
	}

	return prefix.Masked(), nil
}

// AddressesToAllocationPrefixSet converts an allocated IPAddress list to a range-based IPSet.
func AddressesToAllocationPrefixSet(addresses []ipamv1.IPAddress) (*netipx.IPSet, error) {
	builder := &netipx.IPSetBuilder{}
	for _, address := range addresses {
		prefix, err := PrefixFromIPAddress(address)
		if err != nil {
			return nil, err
		}
		builder.AddPrefix(prefix)
	}
	return builder.IPSet()
}

// PrefixesToIPSet converts prefix pool CIDR entries into an IPSet.
// All entries must be valid, network-aligned CIDRs.
func PrefixesToIPSet(prefixes []string) (*netipx.IPSet, error) {
	builder := &netipx.IPSetBuilder{}
	for _, entry := range prefixes {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid pool CIDR %q: %w", entry, err)
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("pool CIDR %q is not network aligned", entry)
		}
		builder.AddPrefix(prefix)
	}
	return builder.IPSet()
}

func prefixPoolBlockedIPSet(poolConfig *PrefixPoolConfig, inUseIPSet *netipx.IPSet) (*netipx.IPSet, error) {
	builder := &netipx.IPSetBuilder{}

	if len(poolConfig.ExcludedPrefixes) > 0 {
		excludedIPSet, err := AddressesToIPSet(poolConfig.ExcludedPrefixes)
		if err != nil {
			return nil, err
		}
		builder.AddSet(excludedIPSet)
	}

	// Gateway is NOT added to the blocked set for prefix pools.
	// It is carried to IPAddress.Spec.Gateway for informational purposes
	// but does not prevent any prefix from being allocated.

	if inUseIPSet != nil {
		builder.AddSet(inUseIPSet)
	}

	return builder.IPSet()
}

func sortedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	sorted := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(sorted, func(i, j int) bool {
		if cmp := sorted[i].Addr().Compare(sorted[j].Addr()); cmp != 0 {
			return cmp < 0
		}
		return sorted[i].Bits() < sorted[j].Bits()
	})
	return sorted
}

func findFreePrefixInAggregate(aggregate netip.Prefix, targetBits int, blockedIPSet *netipx.IPSet) (netip.Prefix, bool) {
	if !aggregate.IsValid() {
		return netip.Prefix{}, false
	}

	bits := aggregate.Bits()
	if bits > targetBits || bits < 0 || targetBits > aggregate.Addr().BitLen() {
		return netip.Prefix{}, false
	}

	if blockedIPSet.ContainsPrefix(aggregate) {
		return netip.Prefix{}, false
	}

	if !blockedIPSet.OverlapsPrefix(aggregate) {
		if bits == targetBits {
			return aggregate, true
		}
		return netip.PrefixFrom(aggregate.Addr(), targetBits).Masked(), true
	}

	if bits == targetBits {
		return netip.Prefix{}, false
	}

	left, right, ok := splitPrefix(aggregate)
	if !ok {
		return netip.Prefix{}, false
	}

	if prefix, found := findFreePrefixInAggregate(left, targetBits, blockedIPSet); found {
		return prefix, true
	}
	return findFreePrefixInAggregate(right, targetBits, blockedIPSet)
}

func countAllocatablePrefixesInAggregate(aggregate netip.Prefix, targetBits int, blockedIPSet *netipx.IPSet) int {
	if !aggregate.IsValid() {
		return 0
	}

	bits := aggregate.Bits()
	if bits > targetBits || bits < 0 || targetBits > aggregate.Addr().BitLen() {
		return 0
	}

	if blockedIPSet.ContainsPrefix(aggregate) {
		return 0
	}

	if !blockedIPSet.OverlapsPrefix(aggregate) {
		return twoPowerCapped(targetBits - bits)
	}

	if bits == targetBits {
		return 0
	}

	left, right, ok := splitPrefix(aggregate)
	if !ok {
		return 0
	}

	leftCount := countAllocatablePrefixesInAggregate(left, targetBits, blockedIPSet)
	rightCount := countAllocatablePrefixesInAggregate(right, targetBits, blockedIPSet)
	return addIntCapped(leftCount, rightCount)
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, false
	}

	bits := prefix.Bits()
	if bits >= prefix.Addr().BitLen() || bits < 0 {
		return netip.Prefix{}, netip.Prefix{}, false
	}

	left := netip.PrefixFrom(prefix.Addr(), bits+1).Masked()
	rightAddr := netipx.RangeOfPrefix(left).To().Next()
	if !rightAddr.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	right := netip.PrefixFrom(rightAddr, bits+1).Masked()

	return left, right, true
}

func twoPowerCapped(exponent int) int {
	if exponent < 0 {
		return 0
	}
	if exponent == 0 {
		return 1
	}

	total := big.NewInt(1)
	total.Lsh(total, uint(exponent))

	maxInt := big.NewInt(int64(math.MaxInt))
	if total.Cmp(maxInt) > 0 {
		return math.MaxInt
	}
	return int(total.Int64())
}

func addIntCapped(current, add int) int {
	if current == math.MaxInt || add == math.MaxInt {
		return math.MaxInt
	}
	if add > math.MaxInt-current {
		return math.MaxInt
	}
	return current + add
}
