# Budget Hierarchy Pagination Enhancement

## Overview

Enhanced the `get_budget_hierarchy` query to allow users to control pagination at each level of the hierarchy, providing fine-grained control over the amount of data returned.

## Changes Made

### 1. Message Definition (msg.rs)

Updated `GetBudgetHierarchy` query message to accept pagination parameters:

```rust
GetBudgetHierarchy { 
    gaa_id: String,
    pap_page: Option<u32>,           // NEW: Page number for PAP pagination
    paps_per_page: Option<u32>,
    saros_per_pap: Option<u32>,
    ncas_per_saro: Option<u32>,
    obligations_per_saro: Option<u32>,
    dvs_per_parent: Option<u32>,
    disbursements_per_dv: Option<u32>,
}
```

### 2. Query Function (contract.rs)

Updated `get_budget_hierarchy` function to:
- Accept all pagination parameters including `pap_page`
- Calculate offset based on page number: `offset = (page - 1) × paps_per_page`
- Load all PAPs and apply skip/take for pagination
- Apply defaults (100) and max limits (1000) for each level
- Pass limits to child query functions

```rust
pub fn get_budget_hierarchy(
    deps: Deps,
    gaa_id: String,
    pap_page: Option<u32>,           // Page number (default: 1)
    paps_per_page: Option<u32>,
    saros_per_pap: Option<u32>,
    ncas_per_saro: Option<u32>,
    obligations_per_saro: Option<u32>,
    dvs_per_parent: Option<u32>,
    disbursements_per_dv: Option<u32>,
) -> StdResult<BudgetHierarchyResponse>
```

### 3. Query Handler (contract.rs)

Updated query message handler to destructure and pass all parameters.

## Usage Examples

### Default Behavior (100 items per level)
```bash
qadenad query wasm contract-state smart "$CONTRACT" \
  '{"get_budget_hierarchy":{"gaa_id":"gaa_2024"}}'
```

### Custom Pagination with Page Selection
```bash
# Get page 2 of PAPs (items 51-100 if paps_per_page=50)
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "pap_page": 2,
      "paps_per_page": 50,
      "saros_per_pap": 20,
      "ncas_per_saro": 10,
      "obligations_per_saro": 10,
      "dvs_per_parent": 5,
      "disbursements_per_dv": 3
    }
  }'
```

### Minimal Hierarchy (Performance Optimized)
```bash
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "paps_per_page": 10,
      "saros_per_pap": 5,
      "ncas_per_saro": 3,
      "obligations_per_saro": 3,
      "dvs_per_parent": 2,
      "disbursements_per_dv": 2
    }
  }'
```

### Maximum Data (for complete tree)
```bash
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "paps_per_page": 1000,
      "saros_per_pap": 1000,
      "ncas_per_saro": 1000,
      "obligations_per_saro": 1000,
      "dvs_per_parent": 1000,
      "disbursements_per_dv": 1000
    }
  }'
```

## Pagination Parameters

| Parameter | Default | Maximum | Description |
|-----------|---------|---------|-------------|
| `pap_page` | 1 | - | Page number for PAP pagination (1-indexed) |
| `paps_per_page` | 100 | 1000 | PAPs to load per page |
| `saros_per_pap` | 100 | 1000 | SAROs to load per PAP |
| `ncas_per_saro` | 100 | 1000 | NCAs to load per SARO |
| `obligations_per_saro` | 100 | 1000 | Obligations to load per SARO |
| `dvs_per_parent` | 100 | 1000 | DVs to load per Obligation/NCA |
| `disbursements_per_dv` | 100 | 1000 | Disbursements to load per DV |

### PAP Pagination Logic
- **Page 1**: PAPs 1-100 (if `paps_per_page` = 100)
- **Page 2**: PAPs 101-200
- **Page 3**: PAPs 201-300
- **Formula**: `offset = (pap_page - 1) × paps_per_page`

## Use Cases

### 1. Dashboard Overview (Minimal Data)
For quick dashboard displays showing summary information:
```json
{
  "paps_per_page": 10,
  "saros_per_pap": 5,
  "ncas_per_saro": 3,
  "obligations_per_saro": 3,
  "dvs_per_parent": 2,
  "disbursements_per_dv": 2
}
```

### 2. Department View (Moderate Data)
For department-level analysis:
```json
{
  "paps_per_page": 50,
  "saros_per_pap": 20,
  "ncas_per_saro": 10,
  "obligations_per_saro": 10,
  "dvs_per_parent": 5,
  "disbursements_per_dv": 5
}
```

### 3. Complete Audit (Maximum Data)
For comprehensive audits or reports:
```json
{
  "paps_per_page": 1000,
  "saros_per_pap": 1000,
  "ncas_per_saro": 1000,
  "obligations_per_saro": 1000,
  "dvs_per_parent": 1000,
  "disbursements_per_dv": 1000
}
```

### 4. Frontend Graph Visualization (Balanced)
For interactive graph displays:
```json
{
  "paps_per_page": 20,
  "saros_per_pap": 10,
  "ncas_per_saro": 5,
  "obligations_per_saro": 5,
  "dvs_per_parent": 3,
  "disbursements_per_dv": 3
}
```

## Performance Considerations

### Query Cost
The total number of items loaded is multiplicative:
```
Total Items = paps × (saros × (ncas × dvs + obligations × dvs × disbursements))
```

**Example with defaults (100 each):**
- Worst case: 100 PAPs × 100 SAROs × (100 NCAs × 100 DVs + 100 Obligations × 100 DVs × 100 Disbursements)
- This could be millions of items!

**Recommended for production:**
- Use smaller limits for interactive queries
- Use larger limits for batch/report generation
- Consider the hierarchy depth when setting limits

### Gas Costs
- Each level of pagination adds to gas cost
- Deeper hierarchies with more items cost more gas
- Balance between completeness and cost

## API Integration

### Go Backend Example
```go
// Build query with custom pagination
query := map[string]interface{}{
    "get_budget_hierarchy": map[string]interface{}{
        "gaa_id": gaaID,
        "paps_per_page": papsPerPage,
        "saros_per_pap": sarosPerPap,
        "ncas_per_saro": ncasPerSaro,
        "obligations_per_saro": obligationsPerSaro,
        "dvs_per_parent": dvsPerParent,
        "disbursements_per_dv": disbursementsPerDV,
    },
}

queryJSON, _ := json.Marshal(query)
// Execute query...
```

### Frontend Example
```javascript
const fetchHierarchy = async (gaaId, pagination = {}) => {
  const query = {
    get_budget_hierarchy: {
      gaa_id: gaaId,
      pap_page: pagination.papPage || 1,
      paps_per_page: pagination.papsPerPage || 100,
      saros_per_pap: pagination.sarosPerPap || 100,
      ncas_per_saro: pagination.ncasPerSaro || 100,
      obligations_per_saro: pagination.obligationsPerSaro || 100,
      dvs_per_parent: pagination.dvsPerParent || 100,
      disbursements_per_dv: pagination.disbursementsPerDv || 100,
    }
  };
  
  const response = await queryContract(contractAddress, query);
  return response;
};

// Usage - Page 1
const hierarchyPage1 = await fetchHierarchy('gaa_2024', {
  papPage: 1,
  papsPerPage: 20,
  sarosPerPap: 10,
  ncasPerSaro: 5,
  obligationsPerSaro: 5,
  dvsPerParent: 3,
  disbursementsPerDv: 3
});

// Usage - Page 2
const hierarchyPage2 = await fetchHierarchy('gaa_2024', {
  papPage: 2,
  papsPerPage: 20,
  sarosPerPap: 10,
  ncasPerSaro: 5,
  obligationsPerSaro: 5,
  dvsPerParent: 3,
  disbursementsPerDv: 3
});
```

## Benefits

1. **Flexible Data Loading**: Users control how much data to fetch
2. **Performance Optimization**: Smaller queries for faster responses
3. **Cost Control**: Reduce gas costs by limiting data
4. **Use Case Specific**: Different pagination for different scenarios
5. **Backward Compatible**: All parameters are optional with sensible defaults
6. **PAP Pagination**: Navigate through large PAP lists page by page
7. **Efficient Navigation**: Load only the PAPs needed for current view

## Future Enhancements

1. **Pagination Tokens**: Add `start_after` support for each level to enable true pagination
2. **Depth Control**: Add a `max_depth` parameter to limit hierarchy depth
3. **Filtering**: Add filter parameters (e.g., by agency, date range)
4. **Aggregation**: Add option to return only summaries without details
5. **Caching**: Implement caching for frequently accessed hierarchies

## Notes

- All parameters are optional - omitted values use defaults
- Maximum limit of 1000 per level prevents excessive queries
- The `disbursements_per_dv` parameter is prepared for future use when Disbursements are added to the response structure
- Consider your use case when setting limits - more data = higher gas cost

---

**Status**: ✅ **IMPLEMENTED**

The budget hierarchy query now supports fine-grained pagination control at every level of the hierarchy!
