---
name: update-mac-model-names
description: Add new Apple Mac models to the model-identifier-to-product-name table behind macos.hardware.fullDisplayName. Use when Apple ships new Macs (MacBook Pro, MacBook Air, Mac mini, Mac Studio, Mac Pro, iMac), when fullDisplayName returns a bare identifier such as "Mac17,5" instead of a product name, or when asked to refresh or check the Mac model names.
---

# Update Mac model names

`macos.hardware.fullDisplayName` looks up `machineModel` (for example `Mac16,8`) in
`macosFullDisplayNames` in `providers/os/resources/macos_hardware_names.go` and returns the
product name (`MacBook Pro (14-inch, M4 Pro, Nov 2024)`). A model that isn't in the table
comes back as its bare identifier, so every Mac Apple ships after the last update shows
up that way until someone adds it.

## Source: AppleDB

[`littlebyteorg/appledb`](https://github.com/littlebyteorg/appledb) keeps one JSON file per
device under `deviceFiles/<category>/`. The Mac categories are `Mac Pro`, `Mac Studio`,
`Mac mini`, `Macbook Air`, `Macbook Pro`, `Macbook` and `iMac` (the iMac Pro is in `iMac`).
Each file has `identifier` (a string or a list), `name`, and usually `released`.

Clone it sparsely instead of reading files through the GitHub API. One clone costs no API
quota, while one `gh api` call per file can cost hundreds.

## Step 1: Work in a worktree off a fresh `origin/main`

As for any change in this repo.

## Step 2: Fetch AppleDB and extract identifier, name and release date

```bash
APPLEDB="$TMPDIR/appledb"
rm -rf "$APPLEDB"
git clone -q --depth 1 --filter=blob:none --sparse https://github.com/littlebyteorg/appledb.git "$APPLEDB"
git -C "$APPLEDB" sparse-checkout set "deviceFiles/Mac Pro" "deviceFiles/Mac Studio" \
  "deviceFiles/Mac mini" "deviceFiles/Macbook Air" "deviceFiles/Macbook Pro" \
  "deviceFiles/Macbook" "deviceFiles/iMac"

find "$APPLEDB/deviceFiles" -name '*.json' -print0 \
  | xargs -0 jq -r '(.identifier // [] | if type=="string" then [.] else . end)[] as $id
      | "\($id)\t\(.name)\t\(.released // "" | tostring)"' \
  | grep -E '^(Mac|MacBook|MacBookAir|MacBookPro|MacPro|Macmini|iMac|iMacPro)[0-9]+,[0-9]+	' \
  | sort -u > "$TMPDIR/appledb.tsv"
```

The `grep` keeps only identifiers a Mac reports in `machine_model`. It drops Developer
Transition Kits (`ADP*`), PowerPC Macs (`PowerMac*`), and pre-Intel iMacs (`iMac,1`).

## Step 3: Diff against the table

```bash
grep -oE '^	"[A-Za-z]+[0-9]+,[0-9]+": +"[^"]+"' providers/os/resources/macos_hardware_names.go \
  | sed -E 's/^	"([^"]+)": +"([^"]+)"/\1	\2/' | sort > "$TMPDIR/table.tsv"

# Released identifiers missing from the table: these are the ones to add
awk -F'\t' 'NR==FNR{t[$1]=1;next} !($1 in t) && $2 !~ /Unreleased/' \
  "$TMPDIR/table.tsv" "$TMPDIR/appledb.tsv"

# Table names that differ from every AppleDB name for that identifier
awk -F'\t' 'NR==FNR{n[$1]=n[$1] "|" $2; next}
  { if (index(n[$1] "|", "|" $2 "|")==0) print $1 "\t" $2 "\t AppleDB:" n[$1] }' \
  "$TMPDIR/appledb.tsv" "$TMPDIR/table.tsv"
```

The first list is the work. The second list is for review only. Most of its lines are
identifiers that cover several products, which the table merges on purpose (next step).
Change an existing name only when AppleDB shows it is wrong (a wrong chip, size or year),
not just worded differently.

## Step 4: Add the missing entries

- **Skip anything with "Unreleased" in its name.** Those are prototypes.
- **One identifier, several products** (for example `MacPro5,1` is both the Late 2010 and
  the Mid 2012 Mac Pro, and `MacBookAir6,2` is Mid 2013 and Early 2014): write one merged
  name in the style the table already uses. Join years with `/` (`2013/2014`), sizes with `/`
  (`15/17-inch`), and leave out a qualifier that only one of the variants has. Leave out
  `Server` variants that share the identifier. Never add a suffixed key such as
  `MacPro5,1-2010`: `machineModel` can never equal it, and `TestMacosFullDisplayNamesKeys`
  fails on it.
- **Use AppleDB's `name` otherwise.** Where Apple shipped two models with the same name,
  the table keeps a distinguishing chip, port, or graphics qualifier. Check the
  neighbouring entries for the same product line and match their shape.
- **Sort** within each prefix group (`Mac`, `MacBook`, `MacBookAir`, `MacBookPro`, `MacPro`,
  `Macmini`, `iMac`) in the existing order. `gofmt` realigns the values.

## Step 5: Test

```bash
gofmt -w providers/os/resources/macos_hardware_names.go
go test ./providers/os/resources/ -run 'TestMacosFullDisplayName' -count=1
```

Add a case to `TestMacosFullDisplayName` in `macos_hardware_names_test.go` only for a new
shape, such as a new identifier prefix or a new kind of merged name. Label it measured
when the value came from a real Mac's `system_profiler SPHardwareDataType`, or synthetic
when it didn't.

On a Mac you can query, check the live value as well. Run it outside the Claude Code
sandbox, because `system_profiler` returns empty output inside it:

```bash
make providers/build/os && make providers/install/os
mql run local -c 'macos.hardware { machineModel fullDisplayName }'
```

This table is data, not schema: no `.lr` change, no codegen, no `.lr.versions` entry.

## Step 6: Commit and open the PR

Title: `🧹 os: add new Mac models to macos.hardware.fullDisplayName`. In the PR body, list
the identifiers added with their names, and say which merged names you chose.

## Checklist

- [ ] AppleDB cloned sparsely, with no per-file API calls
- [ ] Every released identifier from the first diff list is in the table
- [ ] No "Unreleased" devices and no suffixed keys
- [ ] Identifiers that cover several products have one merged name in the table's style
- [ ] `gofmt` clean, `TestMacosFullDisplayName*` pass
