# Efficient Pagination for Large Datasets

## Problem Identified

The initial `pap_page` implementation had a scalability issue for large datasets:

```rust
// ❌ BAD: Loads ALL 700,000 PAPs into memory
let all_paps: Vec<PAP> = PAPS
    .prefix(gaa_id.clone())
    .range(deps.storage, None, None, Order::Ascending)
    .collect::<StdResult<Vec<_>>>()?;

let offset = ((page - 1) * paps_limit) as usize;
let paps: Vec<PAP> = all_paps.into_iter().skip(offset).take(paps_limit as usize).collect();
```

**With 700,000 PAPs:**
- Loads all 700,000 PAP objects into memory 💥
- Then throws away 699,900 of them
- Massive gas cost and potential out-of-memory

---

## Solution: Dual Pagination Strategy

### ✅ **Option 1: Cursor-Based (MOST EFFICIENT)**

Use `pap_start_after` with the last PAP ID from the previous page:

```rust
// O(limit) - Only reads what you need!
let start = Some(Bound::exclusive((gaa_id.clone(), start_after_id)));
PAPS
    .prefix(gaa_id.clone())
    .range(deps.storage, start, None, Order::Ascending)
    .take(paps_limit as usize)
    .collect()
```

**Performance:**
- **O(limit)** - Only reads 100 items for 100 items
- Works efficiently with millions of PAPs
- No wasted reads

### ⚠️ **Option 2: Page-Based (LESS EFFICIENT)**

Use `pap_page` for simple page numbers:

```rust
// O(page × limit) - Skips through items
let skip_count = ((page - 1) * paps_limit) as usize;
PAPS
    .prefix(gaa_id.clone())
    .range(deps.storage, None, None, Order::Ascending)
    .skip(skip_count)
    .take(paps_limit as usize)
    .collect()
```

**Performance:**
- **O(page × limit)** - For page 7000, skips 699,900 items
- Still reads keys (but not full objects) for skipped items
- Acceptable for small page numbers (< 100)

---

## Usage Examples

### Cursor-Based (Recommended for Large Datasets)

```bash
# Page 1
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "paps_per_page": 100
    }
  }'

# Response includes last PAP ID: "pap_100"

# Page 2 - Use last PAP ID from page 1
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "pap_start_after": "pap_100",
      "paps_per_page": 100
    }
  }'

# Response includes last PAP ID: "pap_200"

# Page 3 - Use last PAP ID from page 2
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "pap_start_after": "pap_200",
      "paps_per_page": 100
    }
  }'
```

### Page-Based (Simple but Less Efficient)

```bash
# Page 1
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "pap_page": 1,
      "paps_per_page": 100
    }
  }'

# Page 2
qadenad query wasm contract-state smart "$CONTRACT" \
  '{
    "get_budget_hierarchy": {
      "gaa_id": "gaa_2024",
      "pap_page": 2,
      "paps_per_page": 100
    }
  }'
```

---

## Performance Comparison

### Scenario: 700,000 PAPs, want page 7000 (items 699,901-700,000)

| Method | Items Read | Gas Cost | Memory |
|--------|------------|----------|--------|
| **Old (collect all)** | 700,000 full objects | 💥 MASSIVE | 💥 MASSIVE |
| **Page-based (skip)** | 700,000 keys only | High | Low |
| **Cursor-based** | 100 full objects | ✅ Low | ✅ Low |

### Scenario: 700,000 PAPs, want page 1 (items 1-100)

| Method | Items Read | Gas Cost | Memory |
|--------|------------|----------|--------|
| **Old (collect all)** | 700,000 full objects | 💥 MASSIVE | 💥 MASSIVE |
| **Page-based (skip)** | 100 full objects | ✅ Low | ✅ Low |
| **Cursor-based** | 100 full objects | ✅ Low | ✅ Low |

---

## When to Use Each Method

### Use **Cursor-Based** (`pap_start_after`) When:
- ✅ Dataset is large (> 10,000 items)
- ✅ Users navigate sequentially (Next/Previous buttons)
- ✅ You can store the last item ID from previous page
- ✅ Performance is critical

### Use **Page-Based** (`pap_page`) When:
- ✅ Dataset is small (< 10,000 items)
- ✅ Users need to jump to specific pages (page 1, 5, 10)
- ✅ Simplicity is more important than performance
- ✅ You need page numbers for UI

---

## Frontend Implementation

### Cursor-Based Pagination (Recommended)

```javascript
const [lastPapId, setLastPapId] = useState(null);
const [papHistory, setPapHistory] = useState([null]); // Track for back button

const fetchNextPage = async () => {
  const query = {
    get_budget_hierarchy: {
      gaa_id: gaaId,
      pap_start_after: lastPapId,
      paps_per_page: 100
    }
  };
  
  const response = await queryContract(contractAddress, query);
  
  // Store last PAP ID for next page
  if (response.paps.length > 0) {
    const lastPap = response.paps[response.paps.length - 1];
    setLastPapId(lastPap.pap.id);
    setPapHistory([...papHistory, lastPap.pap.id]);
  }
  
  return response;
};

const fetchPreviousPage = async () => {
  // Go back in history
  const newHistory = [...papHistory];
  newHistory.pop(); // Remove current
  const previousId = newHistory[newHistory.length - 1];
  
  setPapHistory(newHistory);
  setLastPapId(previousId);
  
  const query = {
    get_budget_hierarchy: {
      gaa_id: gaaId,
      pap_start_after: previousId,
      paps_per_page: 100
    }
  };
  
  return await queryContract(contractAddress, query);
};
```

### Page-Based Pagination (Simple)

```javascript
const [currentPage, setCurrentPage] = useState(1);

const fetchPage = async (page) => {
  const query = {
    get_budget_hierarchy: {
      gaa_id: gaaId,
      pap_page: page,
      paps_per_page: 100
    }
  };
  
  return await queryContract(contractAddress, query);
};

const goToPage = (page) => {
  setCurrentPage(page);
  fetchPage(page);
};
```

---

## Go API Integration

```go
func (h *FTMHandler) GetBudgetHierarchyFromContract(c *gin.Context) {
    gaaID := c.Param("gaa_id")
    
    // Support both pagination methods
    papPage := 0
    if p := c.Query("pap_page"); p != "" {
        parsed, _ := strconv.Atoi(p)
        papPage = parsed
    }
    
    papStartAfter := c.Query("pap_start_after")
    
    papsPerPage := 100
    if p := c.Query("paps_per_page"); p != "" {
        parsed, _ := strconv.Atoi(p)
        papsPerPage = parsed
    }
    
    query := map[string]interface{}{
        "get_budget_hierarchy": map[string]interface{}{
            "gaa_id": gaaID,
            "paps_per_page": papsPerPage,
        },
    }
    
    // Prefer cursor-based if provided
    if papStartAfter != "" {
        query["get_budget_hierarchy"].(map[string]interface{})["pap_start_after"] = papStartAfter
    } else if papPage > 0 {
        query["get_budget_hierarchy"].(map[string]interface{})["pap_page"] = papPage
    }
    
    // Execute query...
}
```

---

## Best Practices

### 1. **For Production with Large Datasets**
```javascript
// ✅ DO: Use cursor-based pagination
{
  "pap_start_after": "last_pap_id_from_previous_page",
  "paps_per_page": 100
}
```

### 2. **For Admin Dashboards**
```javascript
// ✅ OK: Use page-based for small datasets or admin tools
{
  "pap_page": 1,
  "paps_per_page": 50
}
```

### 3. **Hybrid Approach**
```javascript
// Support both in your API
if (startAfter) {
  // Use cursor-based (efficient)
  query.pap_start_after = startAfter;
} else if (page) {
  // Fallback to page-based (simple)
  query.pap_page = page;
}
```

---

## Migration Path

### Phase 1: Current (Both Supported)
- Both `pap_page` and `pap_start_after` work
- Frontend can use either method
- Gradual migration possible

### Phase 2: Optimize Frontend
- Update frontend to use cursor-based pagination
- Keep page-based for backward compatibility
- Monitor performance improvements

### Phase 3: Future (Optional)
- Deprecate `pap_page` for large datasets
- Add warnings for inefficient queries
- Provide migration guide

---

## Summary

| Aspect | Cursor-Based | Page-Based |
|--------|--------------|------------|
| **Efficiency** | ✅ O(limit) | ⚠️ O(page × limit) |
| **Scalability** | ✅ Millions of items | ⚠️ < 10,000 items |
| **Simplicity** | ⚠️ More complex | ✅ Very simple |
| **UI Support** | ⚠️ Next/Prev only | ✅ Jump to any page |
| **Gas Cost** | ✅ Low | ⚠️ High for large pages |
| **Memory** | ✅ Constant | ✅ Constant (with skip) |

**Recommendation:** Use **cursor-based** (`pap_start_after`) for production with large datasets. Keep **page-based** (`pap_page`) for simple use cases and backward compatibility.

---

**Status**: ✅ **IMPLEMENTED**

Both pagination methods are now available with proper efficiency characteristics!
