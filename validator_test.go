package circuits

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func toSet(ids []CircuitID) map[CircuitID]struct{} {
	m := make(map[CircuitID]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

func requireContainsAll(t *testing.T, got []CircuitID, want []CircuitID) {
	t.Helper()
	gotSet := toSet(got)
	for _, w := range want {
		_, ok := gotSet[w]
		require.True(t, ok, "expected to contain %q, got=%v", w, got)
	}
}

func requireEqualAsSet(t *testing.T, got []CircuitID, want []CircuitID) {
	t.Helper()
	require.Equal(t, toSet(want), toSet(got))
}

func TestGetCircuitIdsWithSubVersions_NoFilter_ReturnsAllBaseAndSubVersions(t *testing.T) {
	got := GetCircuitIdsWithSubVersions(nil)

	requireContainsAll(t, got, []CircuitID{
		AtomicQueryMTPV2CircuitID,
		AtomicQueryV3CircuitID,
		AuthV2CircuitID,
		LinkedMultiQuery10CircuitID,
		AtomicQueryV3StableCircuitID,
		AtomicQueryV3OnChainStableCircuitID,
		LinkedMultiQueryStableCircuitID,
	})

	requireContainsAll(t, got, []CircuitID{
		CircuitID(string(AtomicQueryV3StableCircuitID) + "-16-16-64"),
		CircuitID(string(AtomicQueryV3OnChainStableCircuitID) + "-16-16-64-16-32"),
		CircuitID(LinkedMultiQueryStableCircuitID + "3"),
		CircuitID(LinkedMultiQueryStableCircuitID + "5"),
	})
}

func TestGetCircuitIdsWithSubVersions_WithFilter_IncludesOnlyFilteredBasesAndTheirSubVersions(t *testing.T) {
	filter := []CircuitID{
		AtomicQueryV3StableCircuitID,
		LinkedMultiQueryStableCircuitID,
	}

	got := GetCircuitIdsWithSubVersions(filter)

	want := []CircuitID{
		AtomicQueryV3StableCircuitID,
		CircuitID(string(AtomicQueryV3StableCircuitID) + "-16-16-64"),

		LinkedMultiQueryStableCircuitID,
		CircuitID(LinkedMultiQueryStableCircuitID + "3"),
		CircuitID(LinkedMultiQueryStableCircuitID + "5"),
	}

	requireEqualAsSet(t, got, want)

	gotSet := toSet(got)
	_, hasAuthV2 := gotSet[AuthV2CircuitID]
	require.False(t, hasAuthV2)
}

func TestGetCircuitIdsWithSubVersions_FilterWithUnknownIds_ReturnsEmpty(t *testing.T) {
	got := GetCircuitIdsWithSubVersions([]CircuitID{"some-unknown-circuit"})
	require.Empty(t, got)
}

func TestGetGroupedCircuitIdsWithSubVersions_WhenFilterIsBase_ReturnsBasePlusItsSubVersions(t *testing.T) {
	got := GetGroupedCircuitIdsWithSubVersions(AtomicQueryV3StableCircuitID)

	want := []CircuitID{
		AtomicQueryV3StableCircuitID,
		CircuitID(string(AtomicQueryV3StableCircuitID) + "-16-16-64"),
	}
	requireEqualAsSet(t, got, want)
}

func TestGetGroupedCircuitIdsWithSubVersions_WhenFilterIsSubVersion_ReturnsGroupContainingBase(t *testing.T) {
	sub := CircuitID(string(AtomicQueryV3StableCircuitID) + "-16-16-64")

	got := GetGroupedCircuitIdsWithSubVersions(sub)

	want := []CircuitID{
		AtomicQueryV3StableCircuitID,
		sub,
	}
	requireEqualAsSet(t, got, want)
}

func TestGetGroupedCircuitIdsWithSubVersions_Unknown_ReturnsSingleton(t *testing.T) {
	unknown := CircuitID("unknown-circuit-id")
	got := GetGroupedCircuitIdsWithSubVersions(unknown)
	require.Equal(t, []CircuitID{unknown}, got)
}

func TestGetGroupedCircuitIdsWithSubVersions_LinkedMultiQueryStable_SubGroups(t *testing.T) {
	got := GetGroupedCircuitIdsWithSubVersions(LinkedMultiQueryStableCircuitID)

	want := []CircuitID{
		LinkedMultiQueryStableCircuitID,
		CircuitID(LinkedMultiQueryStableCircuitID + "3"),
		CircuitID(LinkedMultiQueryStableCircuitID + "5"),
	}
	requireEqualAsSet(t, got, want)
}

func TestGetGroupedCircuitIdsWithSubVersions_LinkedMultiQueryStable_SubVersionLookup(t *testing.T) {
	sub3 := CircuitID(LinkedMultiQueryStableCircuitID + "3")
	got := GetGroupedCircuitIdsWithSubVersions(sub3)

	want := []CircuitID{
		LinkedMultiQueryStableCircuitID,
		sub3,
		CircuitID(LinkedMultiQueryStableCircuitID + "5"),
	}

	requireEqualAsSet(t, got, want)
}
