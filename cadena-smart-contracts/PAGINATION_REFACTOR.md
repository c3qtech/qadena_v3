# Pagination Refactoring for Efficient Queries

## Overview
This refactoring changes the storage structure from single-key maps with separate index vectors to composite-key maps that enable efficient pagination without loading entire collections into memory.

## Changes Made

### 1. State.rs - Storage Structure
**Before:**
```rust
pub const PAPS: Map<String, PAP> = Map::new("paps");
pub const PAP_BY_GAA: Map<String, Vec<String>> = Map::new("pap_by_gaa");
```

**After:**
```rust
pub const PAPS: Map<(String, String), PAP> = Map::new("paps"); // (gaa_id, pap_id)
// No separate index needed!
```

**All Storage Maps:**
- `GAAS`: `Map<String, GAA>` - No change (no parent)
- `PAPS`: `Map<(String, String), PAP>` - (gaa_id, pap_id)
- `SAROS`: `Map<(String, String), SARO>` - (pap_id, saro_id)
- `OBLIGATIONS`: `Map<(String, String), Obligation>` - (saro_id, obligation_id)
- `NCAS`: `Map<(String, String), NCA>` - (saro_id, nca_id)
- `DISBURSEMENT_VOUCHERS`: `Map<(String, String, String), DisbursementVoucher>` - (obligation_id, nca_id, dv_id)
- `DISBURSEMENTS`: `Map<(String, String), Disbursement>` - (dv_id, disbursement_id)

### 2. Msg.rs - Query Messages
All query messages now support pagination:

```rust
GetPAPsByGAA { 
    gaa_id: String,
    start_after: Option<String>,  // Last pap_id from previous page
    limit: Option<u32>,            // Max items per page (default 30, max 100)
}
```

Single entity queries now require full composite key:
```rust
GetPAP { 
    gaa_id: String,
    pap_id: String,
}
```

### 3. Contract.rs - Implementation Changes Needed

#### Create Functions
Update all create functions to use composite keys:

**Example - create_pap:**
```rust
// OLD:
PAPS.save(deps.storage, id.clone(), &pap)?;
let mut pap_ids = PAP_BY_GAA.may_load(deps.storage, gaa_id.clone())?.unwrap_or_default();
pap_ids.push(id.clone());
PAP_BY_GAA.save(deps.storage, gaa_id.clone(), &pap_ids)?;

// NEW:
PAPS.save(deps.storage, (gaa_id.clone(), id.clone()), &pap)?;
// That's it! No index update needed
```

#### Query Functions
Implement paginated queries using prefix():

```rust
pub fn get_paps_by_gaa(
    deps: Deps,
    gaa_id: String,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Vec<PAP>> {
    let limit = limit.unwrap_or(30).min(100) as usize;
    
    let start = start_after.map(|id| Bound::exclusive((gaa_id.clone(), id)));
    
    PAPS
        .prefix(gaa_id)  // Only iterate PAPs for this GAA
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(_, pap)| pap))
        .collect()
}
```

Single entity queries:
```rust
pub fn get_pap(deps: Deps, gaa_id: String, pap_id: String) -> StdResult<PAP> {
    PAPS.load(deps.storage, (gaa_id, pap_id))
        .map_err(|_| StdError::not_found("PAP"))
}
```

#### Load Functions in Execute
Update all functions that load entities:

```rust
// OLD:
let pap = PAPS.load(deps.storage, pap_id.clone())?;

// NEW:
let pap = PAPS.load(deps.storage, (gaa_id.clone(), pap_id.clone()))?;
```

### 4. Functions to Update in contract.rs

**Execute Functions:**
- `create_pap` - Save with (gaa_id, pap_id), remove index update
- `create_saro` - Save with (pap_id, saro_id), load PAP with composite key
- `create_obligation` - Save with (saro_id, obligation_id), load SARO with composite key
- `create_nca` - Save with (saro_id, nca_id), load SARO with composite key
- `create_disbursement_voucher` - Save with (obligation_id, nca_id, dv_id)
- `create_disbursement` - Save with (dv_id, disbursement_id)

**Query Functions:**
- `get_all_gaas` → `get_gaas` with pagination
- `get_pap` - Add gaa_id parameter
- `get_paps_by_gaa` - Add pagination
- `get_saro` - Add pap_id parameter
- `get_saros_by_pap` - Add pagination
- `get_obligation` - Add saro_id parameter
- `get_obligations_by_saro` - Add pagination
- `get_nca` - Add saro_id parameter
- `get_ncas_by_saro` - Add pagination
- `get_disbursement_voucher` - Add obligation_id and nca_id parameters
- `get_disbursement_vouchers_by_obligation` - Add pagination
- `get_disbursement_vouchers_by_nca` - Add pagination (needs custom impl)
- `get_disbursement` - Add dv_id parameter
- `get_disbursements_by_dv` - Add pagination
- `get_budget_hierarchy` - Update all load calls to use composite keys

### 5. Special Case: DisbursementVouchers by NCA

DVs have two parents (obligation_id, nca_id). To query by NCA:

```rust
pub fn get_dvs_by_nca(
    deps: Deps,
    nca_id: String,
    start_after: Option<(String, String)>,
    limit: Option<u32>,
) -> StdResult<Vec<DisbursementVoucher>> {
    let limit = limit.unwrap_or(30).min(100) as usize;
    
    // Need to scan all DVs and filter by nca_id
    // This is less efficient but necessary for the dual-parent relationship
    let start = start_after.map(|(obl_id, nca_id_inner, dv_id)| 
        Bound::exclusive((obl_id, nca_id_inner, dv_id))
    );
    
    DISBURSEMENT_VOUCHERS
        .range(deps.storage, start, None, Order::Ascending)
        .filter(|item| {
            if let Ok((key, _)) = item {
                key.1 == nca_id  // Filter by nca_id (second element of tuple)
            } else {
                false
            }
        })
        .take(limit)
        .map(|item| item.map(|(_, dv)| dv))
        .collect()
}
```

## Benefits

1. **Constant Write Cost**: Creating entities is O(1), not O(n)
2. **No Memory Explosion**: Never loads millions of IDs into memory
3. **Efficient Queries**: Only reads relevant data
4. **Built-in Pagination**: Uses CosmWasm's native range queries
5. **Less Storage**: No duplicate index vectors
6. **Scalable**: Works with millions of entities per parent

## Migration Notes

**Breaking Changes:**
- All query signatures changed
- API clients need to update query calls
- Test scripts need updating

**Data Migration:**
If there's existing data on-chain, you'll need a migration contract to:
1. Read old single-key format
2. Write to new composite-key format
3. Delete old index maps

## Usage Examples

### Creating Entities (API stays the same)
```javascript
{"create_p_a_p": {
  "id": "pap_001",
  "gaa_id": "gaa_123",
  "amount": "1000000",
  // ... other fields
}}
```

### Querying with Pagination
```javascript
// First page
{"get_p_a_ps_by_g_a_a": {
  "gaa_id": "gaa_123",
  "limit": 100
}}

// Next page (use last pap_id from response)
{"get_p_a_ps_by_g_a_a": {
  "gaa_id": "gaa_123",
  "start_after": "pap_100",
  "limit": 100
}}
```

### Getting Single Entity
```javascript
// OLD: {"get_p_a_p": {"id": "pap_001"}}

// NEW: Must provide parent ID
{"get_p_a_p": {
  "gaa_id": "gaa_123",
  "pap_id": "pap_001"
}}
```

## Implementation Priority

1. ✅ Update `state.rs` storage definitions
2. ✅ Update `msg.rs` query messages
3. ⏳ Update `contract.rs` execute functions (create_*)
4. ⏳ Update `contract.rs` query functions (get_*)
5. ⏳ Update test cases
6. ⏳ Update API client code
7. ⏳ Update test scripts

## Testing Strategy

1. Unit tests for each paginated query
2. Test with 0, 1, 100, 1000+ entities
3. Test pagination boundaries
4. Test start_after edge cases
5. Load test with millions of entities
