# enf_notarial_book — ENF Electronic Notarial Book smart contract

A CosmWasm contract (modeled on the `cadena` PAP pattern) that is the **source of truth** for
the ENF Electronic Notarial Book. Every row the API writes to `electronic_notarial_book_entries`
(on notarization complete / cancel / fail) is also appended here; the chain assigns the
authoritative sequence numbers and the DB row mirrors them.

## Record (`state.rs`)

`NotarialBookEntry` with nested structs (all serialize to JSON on chain):
- `enp: Enp { email, full_name, commission_number }` — the notary, resolved from
  `enp_profiles` → `enf_users` by the backend (no opaque uuid).
- `references: DocRefs { document_id, document_checksum, notarization_session_id,
  certificate: Option<CertificateRef { id, number, notarized_at, content }> }` — the foreign
  keys with their meaningful values; the **full** certificate text is stored on chain.
- `enf_seq` (global) and `enp_seq` (per `enp.email`) are **assigned by the contract**.

## Messages

- `Execute::CreateEntry { id, enp, entry_date, status, mode, notarization_type, document_title,
  document_type, parties, references, cancellation_reason, cancelled_by }` — idempotent on `id`;
  assigns `enf_seq`/`enp_seq`, emits them as tx attributes.
- Queries: `GetEntry { id }`, `GetEntryByEnfSeq { enf_seq }`,
  `GetEntries { start_after, limit }`, `GetEntriesByEnp { enp_email, start_after, limit }`,
  `GetCount {}`.

## Build & deploy

```bash
cargo wasm           # debug/check: build the wasm
./optimizer.sh       # produces artifacts/enf_notarial_book.wasm (reproducible build)
```

Deploy to the Qadena node the same way the `cadena` contract is deployed (store the wasm code,
then instantiate with `{}`), and set `ENF_NOTARIAL_CONTRACT_ADDRESS` in the API environment to
the instantiated contract address.
