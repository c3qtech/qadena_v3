# Pagination Refactoring Progress

## ✅ Completed

### State.rs
- ✅ Updated all storage maps to use composite keys
- ✅ Removed all index maps

### Msg.rs
- ✅ Updated all query messages with pagination support
- ✅ Updated single entity queries to require full composite keys

### Contract.rs - Execute Functions

#### ✅ create_pap (Lines 310-320)
- Uses composite key: `(gaa_id, pap_id)`
- Removed index update
- **Status:** Complete

#### ✅ create_saro (Lines 323-396)
- Finds PAP by iterating (temporary solution)
- Uses composite key: `(pap_id, saro_id)`
- Removed index update
- **Status:** Complete
- **Note:** Iteration for finding PAP is O(n) - can be optimized later

#### ✅ create_obligation (Lines 399-470)
- Finds SARO by iterating (temporary solution)
- Uses composite key: `(saro_id, obligation_id)`
- Removed index update
- **Status:** Complete
- **Note:** Iteration for finding SARO is O(n) - can be optimized later

## ⏳ In Progress / TODO

### Contract.rs - Execute Functions

#### ✅ create_nca (Lines 473-550)
- Finds SARO by iterating
- Uses composite key: `(saro_id, nca_id)`
- Removed index update
- **Status:** Complete

#### ✅ create_disbursement_voucher (Lines 553-650)
- Finds Obligation by iterating
- Finds NCA by iterating
- Uses composite key: `(obligation_id, nca_id, dv_id)`
- Removed index updates (both DV_BY_OBLIGATION and DV_BY_NCA)
- **Status:** Complete

#### ✅ create_disbursement (Lines 652-719)
- Finds DV by iterating (3-tuple key)
- Uses composite key: `(dv_id, disbursement_id)`
- Removed index update
- **Status:** Complete

### Contract.rs - Query Functions

All query functions need to be rewritten to:
1. Use composite keys for loading single entities
2. Implement pagination with `prefix()` and `range()`
3. Handle `start_after` and `limit` parameters

#### ⏳ get_all_gaas → get_gaas
**Needs:** Pagination support

#### ⏳ get_pap
**Needs:** Accept `(gaa_id, pap_id)` parameters

#### ⏳ get_paps_by_gaa
**Needs:** Pagination with `prefix(gaa_id)`

#### ⏳ get_saro
**Needs:** Accept `(pap_id, saro_id)` parameters

#### ⏳ get_saros_by_pap
**Needs:** Pagination with `prefix(pap_id)`

#### ⏳ get_obligation
**Needs:** Accept `(saro_id, obligation_id)` parameters

#### ⏳ get_obligations_by_saro
**Needs:** Pagination with `prefix(saro_id)`

#### ⏳ get_nca
**Needs:** Accept `(saro_id, nca_id)` parameters

#### ⏳ get_ncas_by_saro
**Needs:** Pagination with `prefix(saro_id)`

#### ⏳ get_disbursement_voucher
**Needs:** Accept `(obligation_id, nca_id, dv_id)` parameters

#### ⏳ get_disbursement_vouchers_by_obligation
**Needs:** Pagination with `prefix(obligation_id)`

#### ⏳ get_disbursement_vouchers_by_nca
**Needs:** Custom iteration filtering by nca_id (2nd element of 3-tuple)

#### ⏳ get_disbursement
**Needs:** Accept `(dv_id, disbursement_id)` parameters

#### ⏳ get_disbursements_by_dv
**Needs:** Pagination with `prefix(dv_id)`

#### ⏳ get_budget_hierarchy
**Needs:** Update all entity loading to use composite keys

### Contract.rs - Query Message Handler

The `query()` function needs to be updated to match new message signatures:

```rust
match msg {
    QueryMsg::GetGAA { id } => to_json_binary(&query::get_gaa(deps, id)?),
    QueryMsg::GetGAAs { start_after, limit } => to_json_binary(&query::get_gaas(deps, start_after, limit)?),
    QueryMsg::GetPAP { gaa_id, pap_id } => to_json_binary(&query::get_pap(deps, gaa_id, pap_id)?),
    QueryMsg::GetPAPsByGAA { gaa_id, start_after, limit } => to_json_binary(&query::get_paps_by_gaa(deps, gaa_id, start_after, limit)?),
    // ... etc
}
```

## Optimization Opportunities

### Reverse Index Maps (Optional)
To avoid O(n) iteration when finding parent IDs, we could add lightweight reverse indexes:

```rust
// In state.rs
pub const PAP_TO_GAA: Map<String, String> = Map::new("pap_to_gaa");
pub const SARO_TO_PAP: Map<String, String> = Map::new("saro_to_pap");
pub const OBLIGATION_TO_SARO: Map<String, String> = Map::new("obligation_to_saro");
pub const NCA_TO_SARO: Map<String, String> = Map::new("nca_to_saro");
pub const DV_TO_PARENTS: Map<String, (String, String)> = Map::new("dv_to_parents"); // (obligation_id, nca_id)
pub const DISBURSEMENT_TO_DV: Map<String, String> = Map::new("disbursement_to_dv");
```

**Trade-offs:**
- **Pro:** O(1) parent lookup instead of O(n) iteration
- **Pro:** Simpler code in create functions
- **Con:** Additional storage (but much smaller than old Vec indexes)
- **Con:** Extra write on create

**Recommendation:** Add these if iteration becomes a performance bottleneck.

## Testing Checklist

- [ ] Compile contract successfully
- [ ] Unit tests for each create function
- [ ] Unit tests for each query function
- [ ] Test pagination boundaries (0, 1, 100, 1000+ items)
- [ ] Test start_after edge cases
- [ ] Update integration tests
- [ ] Update test_cadena.sh script
- [ ] Update API client code

## Next Steps

1. Complete remaining execute functions (create_nca, create_disbursement_voucher, create_disbursement)
2. Implement all query functions with pagination
3. Update query message handler
4. Run cargo build and fix compilation errors
5. Update test cases
6. Update API and test scripts
