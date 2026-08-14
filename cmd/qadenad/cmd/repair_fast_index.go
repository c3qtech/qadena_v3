package cmd

import (
	"fmt"
	"path/filepath"

	"cosmossdk.io/log"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/iavl"
	iavldb "github.com/cosmos/iavl/db"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
)

// storageVersionKey is iavl's metadata marker, written as 'm'+"storage_version".  Its value is
// "<storage version>-<version the fast index was last built at>"; anything >= "1.1.0" means iavl
// considers the fast index present and will never rebuild it.
var storageVersionKey = append([]byte("m"), []byte("storage_version")...)

// newRepairFastIndexCmd rebuilds the fast-node index of stores that a snapshot restore left empty.
//
// THE FAULT IT REPAIRS.  A restore imports IAVL tree nodes only.  Reads are served from the FAST
// INDEX -- derived state, absent from the snapshot format, rebuilt lazily by iavl on load and then
// marked complete.  When the rebuild runs before the imported nodes are durable it walks a tree that
// yields nothing, writes ZERO fast nodes, and stamps the marker anyway; the nodes land immediately
// afterwards.  The result is a store whose tree is perfect and whose every read returns nil, with the
// marker guaranteeing it is never rebuilt.  Only stores larger than iavl's 10,000-node async flush
// are exposed, which is why it presents as one arbitrary module losing all its state.
//
// THE REPAIR.  Delete the marker and load the tree.  iavl then sees an un-upgraded store, walks the
// tree -- now fully durable, which is why this works where the original attempt failed -- and writes
// one fast node per entry.  No re-sync, no chain interaction, no enclave: the data has been on disk
// the whole time and only the index derived from it was missing.
//
// This does not fix the underlying race (that belongs in iavl's Importer.Commit, which must wait for
// its in-flight batch before making the version visible).  It repairs databases already damaged by
// it, which re-syncing is otherwise the only way to fix.
func newRepairFastIndexCmd(defaultNodeHome string) *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "repair-fast-index",
		Short: "rebuild fast-node indexes left empty by a snapshot restore",
		Long: `
Rebuilds the IAVL fast-node index for any store that commits to a non-empty hash but reads as
empty -- the state a state-synced node is left in when the index was not rebuilt after the
restore.

The tree itself is intact in that state and is not modified: this only regenerates the index
derived from it, so it is safe to run on a healthy node (stores that are already correct are
reported and skipped).

qadenad must be STOPPED; this opens the application database for writing. The enclave is not
involved and need not be running.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := server.GetServerContextFromCmd(cmd)
			home := ctx.Config.RootDir

			db, err := dbm.NewDB("application", server.GetAppDBBackend(ctx.Viper), filepath.Join(home, "data"))
			if err != nil {
				return fmt.Errorf("open application db (is qadenad still running?): %w", err)
			}
			defer db.Close()

			version := rootmulti.GetLatestVersion(db)
			if version == 0 {
				return fmt.Errorf("no committed version in %s -- nothing to repair", filepath.Join(home, "data"))
			}

			// Read the store list from the commit info rather than hardcoding it, so this stays
			// correct as modules are added.
			rs := rootmulti.NewStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
			commitInfo, err := rs.GetCommitInfo(version)
			if err != nil {
				return fmt.Errorf("read commit info at version %d: %w", version, err)
			}

			cmd.Printf("application db at version %d, %d stores\n\n", version, len(commitInfo.StoreInfos))

			repaired, healthy, skipped := 0, 0, 0
			for _, si := range commitInfo.StoreInfos {
				name := si.Name
				view := dbm.NewPrefixDB(db, []byte("s/k:"+name+"/"))

				// A store with no tree of its own (transient, memory, or genuinely empty) has
				// nothing to index and nothing to diagnose.
				probe := iavl.NewMutableTree(iavldb.NewWrapper(view), 0, false, iavl.NewNopLogger())
				loaded, err := probe.Load()
				if err != nil || loaded == 0 {
					skipped++
					continue
				}
				immutable, err := probe.GetImmutable(loaded)
				if err != nil {
					skipped++
					continue
				}
				treeEntries := immutable.Size()
				if treeEntries == 0 {
					skipped++
					continue
				}

				// What a keeper would actually see: reads go through the fast index.
				readable := int64(0)
				if it, ierr := immutable.Iterator(nil, nil, true); ierr == nil {
					for ; it.Valid() && readable < treeEntries; it.Next() {
						readable++
					}
					it.Close()
				}

				if readable == treeEntries {
					cmd.Printf("  %-16s ok        %d entries\n", name, treeEntries)
					healthy++
					continue
				}

				cmd.Printf("  %-16s BROKEN    tree holds %d entries, reads yield %d\n", name, treeEntries, readable)
				if dryRun {
					repaired++
					continue
				}

				if err := view.Delete(storageVersionKey); err != nil {
					return fmt.Errorf("%s: clear fast-storage marker: %w", name, err)
				}

				// Loading with the marker gone is what triggers the rebuild.
				rebuilt := iavl.NewMutableTree(iavldb.NewWrapper(view), 0, false, iavl.NewNopLogger())
				v, err := rebuilt.Load()
				if err != nil {
					return fmt.Errorf("%s: reload after clearing marker: %w", name, err)
				}
				after, err := rebuilt.GetImmutable(v)
				if err != nil {
					return fmt.Errorf("%s: reopen after rebuild: %w", name, err)
				}
				verified := int64(0)
				if it, ierr := after.Iterator(nil, nil, true); ierr == nil {
					for ; it.Valid(); it.Next() {
						verified++
					}
					it.Close()
				}
				if verified != treeEntries {
					return fmt.Errorf("%s: repair did not take -- tree holds %d entries, reads still yield %d. "+
						"The index is not the fault here; this store is genuinely incomplete and the node must re-join",
						name, treeEntries, verified)
				}
				cmd.Printf("  %-16s REPAIRED  %d entries now readable\n", name, verified)
				repaired++
			}

			cmd.Printf("\n%d repaired, %d already healthy, %d without a tree to check\n", repaired, healthy, skipped)
			if dryRun && repaired > 0 {
				cmd.Printf("(--dry-run: nothing was written)\n")
			}
			if repaired == 0 {
				cmd.Printf("nothing needed repair\n")
			}
			return nil
		},
	}

	cmd.Flags().String(flags.FlagHome, defaultNodeHome, "The application home directory")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be repaired without writing")

	return cmd
}
