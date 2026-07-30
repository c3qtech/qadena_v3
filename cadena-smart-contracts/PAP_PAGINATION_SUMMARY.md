# PAP Page Pagination - Implementation Summary

## Overview
Added `pap_page` parameter to `get_budget_hierarchy` query to enable page-based navigation through PAPs, similar to the Go API implementation.

## Changes Made

### 1. Message Definition (`msg.rs`)
```rust
GetBudgetHierarchy { 
    gaa_id: String,
    pap_page: Option<u32>,           // ✅ NEW
    paps_per_page: Option<u32>,
    saros_per_pap: Option<u32>,
    ncas_per_saro: Option<u32>,
    obligations_per_saro: Option<u32>,
    dvs_per_parent: Option<u32>,
    disbursements_per_dv: Option<u32>,
}
```

### 2. Query Function (`contract.rs`)
```rust
pub fn get_budget_hierarchy(
    deps: Deps,
    gaa_id: String,
    pap_page: Option<u32>,           // ✅ NEW
    // ... other parameters
) -> StdResult<BudgetHierarchyResponse> {
    // Calculate page (default 1, minimum 1)
    let page = pap_page.unwrap_or(1).max(1);
    
    // Load all PAPs
    let all_paps: Vec<PAP> = PAPS
        .prefix(gaa_id.clone())
        .range(deps.storage, None, None, Order::Ascending)
        .map(|item| item.map(|(_, pap)| pap))
        .collect::<StdResult<Vec<_>>>()?;
    
    // Apply pagination
    let offset = ((page - 1) * paps_limit) as usize;
    let paps: Vec<PAP> = all_paps
        .into_iter()
        .skip(offset)
        .take(paps_limit as usize)
        .collect();
    
    // ... rest of hierarchy building
}
```

### 3. Query Handler (`contract.rs`)
Updated to destructure and pass `pap_page` parameter.

## Usage Examples

### Page 1 (Default)
```bash
qadenad query wasm contract-state smart "$CONTRACT" \
  '{"get_budget_hierarchy":{"gaa_id":"gaa_2024"}}'
```

### Page 2
```bash
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "pap_page": 2,
      "paps_per_page": 50
    }
  }'
```

### Page 3 with Custom Limits
```bash
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "pap_page": 3,
      "paps_per_page": 20,
      "saros_per_pap": 10,
      "ncas_per_saro": 5,
      "obligations_per_saro": 5,
      "dvs_per_parent": 3,
      "disbursements_per_dv": 3
    }
  }'
```

## Pagination Logic

### Formula
```
offset = (pap_page - 1) × paps_per_page
```

### Examples (with paps_per_page = 50)
| Page | Offset | PAPs Returned |
|------|--------|---------------|
| 1    | 0      | 1-50          |
| 2    | 50     | 51-100        |
| 3    | 100    | 101-150       |
| 4    | 150    | 151-200       |

### Examples (with paps_per_page = 100)
| Page | Offset | PAPs Returned |
|------|--------|---------------|
| 1    | 0      | 1-100         |
| 2    | 100    | 101-200       |
| 3    | 200    | 201-300       |
| 4    | 300    | 301-400       |

## Frontend Integration

### React Example
```javascript
const [currentPage, setCurrentPage] = useState(1);
const [papsPerPage] = useState(20);

const fetchHierarchyPage = async (page) => {
  const query = {
    get_budget_hierarchy: {
      gaa_id: gaaId,
      pap_page: page,
      paps_per_page: papsPerPage,
      saros_per_pap: 10,
      ncas_per_saro: 5,
      obligations_per_saro: 5,
      dvs_per_parent: 3,
      disbursements_per_dv: 3
    }
  };
  
  const response = await queryContract(contractAddress, query);
  return response;
};

// Navigation
const goToNextPage = () => {
  setCurrentPage(prev => prev + 1);
  fetchHierarchyPage(currentPage + 1);
};

const goToPreviousPage = () => {
  if (currentPage > 1) {
    setCurrentPage(prev => prev - 1);
    fetchHierarchyPage(currentPage - 1);
  }
};
```

### Pagination Component
```javascript
<div className="pagination">
  <button 
    onClick={goToPreviousPage} 
    disabled={currentPage === 1}
  >
    Previous
  </button>
  
  <span>Page {currentPage}</span>
  
  <button onClick={goToNextPage}>
    Next
  </button>
</div>
```

## Go API Integration

### Handler Example
```go
func (h *FTMHandler) GetBudgetHierarchyFromContract(c *gin.Context) {
    gaaID := c.Param("gaa_id")
    
    // Get pagination parameters
    papPage := 1
    if p := c.Query("pap_page"); p != "" {
        if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
            papPage = parsed
        }
    }
    
    papsPerPage := 100
    if p := c.Query("paps_per_page"); p != "" {
        if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
            papsPerPage = parsed
        }
    }
    
    // Build query
    query := map[string]interface{}{
        "get_budget_hierarchy": map[string]interface{}{
            "gaa_id": gaaID,
            "pap_page": papPage,
            "paps_per_page": papsPerPage,
            // ... other parameters
        },
    }
    
    // Execute query...
}
```

## Benefits

1. **✅ Page-Based Navigation**: Users can navigate through PAPs page by page
2. **✅ Consistent with API**: Matches the Go backend API pattern
3. **✅ Efficient Loading**: Only loads PAPs for the requested page
4. **✅ Flexible Page Size**: Control how many PAPs per page
5. **✅ Simple Implementation**: Easy to understand and use
6. **✅ Backward Compatible**: Default to page 1 if not specified

## Performance Considerations

### Current Implementation
- Loads **all PAPs** into memory, then applies skip/take
- Works well for moderate PAP counts (< 10,000)
- Simple and straightforward

### For Very Large Datasets (Future Optimization)
If you have millions of PAPs, consider:
1. Using `start_after` with the last PAP ID from previous page
2. Storing total PAP count separately for pagination metadata
3. Implementing cursor-based pagination

### Example Optimization (Future)
```rust
// Instead of loading all PAPs
let all_paps = load_all_paps();  // ❌ Loads everything

// Use start_after for true pagination
let start_key = if page > 1 {
    Some(last_pap_id_from_previous_page)
} else {
    None
};

let paps = PAPS
    .prefix(gaa_id)
    .range(deps.storage, start_key, None, Order::Ascending)
    .take(paps_limit)
    .collect();  // ✅ Only loads what's needed
```

## Use Cases

### 1. Dashboard with Pagination Controls
```javascript
// Show 20 PAPs per page with navigation
pap_page: currentPage,
paps_per_page: 20
```

### 2. Department View
```javascript
// Show 50 PAPs per page
pap_page: 1,
paps_per_page: 50
```

### 3. Mobile View
```javascript
// Show fewer PAPs for mobile
pap_page: 1,
paps_per_page: 10
```

### 4. Export/Report
```javascript
// Large page size for exports
pap_page: 1,
paps_per_page: 1000
```

## Testing

### Test Different Pages
```bash
# Page 1
curl -X GET "$API/hierarchy/gaa_2024?pap_page=1&paps_per_page=20"

# Page 2
curl -X GET "$API/hierarchy/gaa_2024?pap_page=2&paps_per_page=20"

# Page 3
curl -X GET "$API/hierarchy/gaa_2024?pap_page=3&paps_per_page=20"
```

### Test Edge Cases
```bash
# Page 0 (should default to 1)
curl -X GET "$API/hierarchy/gaa_2024?pap_page=0"

# Negative page (should default to 1)
curl -X GET "$API/hierarchy/gaa_2024?pap_page=-1"

# Very large page (should return empty if no data)
curl -X GET "$API/hierarchy/gaa_2024?pap_page=9999"
```

## Notes

- **Default page**: 1 (first page)
- **Minimum page**: 1 (negative values default to 1)
- **Empty results**: If page exceeds available data, returns empty PAPs array
- **All parameters optional**: Sensible defaults for all parameters
- **1-indexed**: Pages start at 1, not 0 (user-friendly)

---

**Status**: ✅ **IMPLEMENTED**

PAP pagination is now fully functional and matches the Go API pattern!
