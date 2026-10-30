# ADR: mql SBOM Cataloger for WordPress Plugins

**Status:** Proposed
**Date:** 2026-04-18

---

## Context

cnspec needs native SBOM cataloging for WordPress plugins to detect which plugins (and versions) are installed on WordPress instances. WordPress powers over 40% of the web, and plugins are a major supply chain attack vector — vulnerable plugins are the leading cause of WordPress compromises.

WordPress plugins are stored in `wp-content/plugins/<plugin-name>/` and contain a `readme.txt` file with standardized headers including name, version, and license.

## Data Gathering

### Primary: readme.txt header parsing

Each WordPress plugin directory contains a `readme.txt` with headers:

```
=== Akismet Anti-spam: Spam Protection ===
Contributors: automattic, ...
Stable tag: 5.3.3
Requires at least: 5.8
Tested up to: 6.6
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
```

Key headers:
- `=== Plugin Name ===` (first line): Display name
- `Stable tag`: Installed version
- `License`: License name
- `Requires at least`: Minimum WordPress version
- `Tested up to`: Maximum tested WordPress version

### Alternative: PHP file header parsing

Plugin PHP files also contain metadata headers, but `readme.txt` is more standardized and doesn't require PHP parsing. The main PHP file header is used as fallback when readme.txt is missing.

### Discovery

Scan `wp-content/plugins/` for subdirectories containing `readme.txt`. Common locations:
- `/var/www/html/wp-content/plugins/`
- `/var/www/wordpress/wp-content/plugins/`

## Resource Schema

| Field | Type | Source |
|-------|------|--------|
| `name` | string | Directory name (plugin slug) |
| `version` | string | `Stable tag` header |
| `purl` | string | `pkg:wordpress-plugin/<name>@<version>` |
| `displayName` | string | `=== Name ===` first line |
| `license` | string | `License` header |
| `requiresWp` | string | `Requires at least` header |
| `testedUpTo` | string | `Tested up to` header |

## Verification

- Fixture-based tests with real WordPress plugin readme.txt files
- Interactive: `mql run os -c "wordpress.packages(path: '/var/www/html/wp-content/plugins') { list { name version } }"`
