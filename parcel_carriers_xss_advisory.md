# modified eCommerce Shopsoftware - Stored Cross-Site Scripting (XSS) in `admin/parcel_carriers.php`

| Field                 | Value                                                                                                                       |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Advisory ID**       | VEX-2026-002                                                                                                                |
| **Title**             | Stored Cross-Site Scripting (XSS) in `admin/parcel_carriers.php`                                                            |
| **Affected Product**  | modified eCommerce Shopsoftware                                                                                             |
| **Affected Versions** | <=v3.3.0                                                                                                                    |
| **Fixed Versions**    | none available at time of writing                                                                                           |
| **CWE**               | CWE-79: Improper Neutralization of Input During Web Page Generation                                                         |
| **CVSS v3.1 Score**   | 3.5 (Low)                                                                                                                   |
| **CVSS v3.1 Vector**  | AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N                                                                                         |
| **CVE ID**            | *pending / not assigned / CVE-YYYY-NNNNN*                                                                                   |
| **Reporter**          | [V1r4l3xpl017](https://github.com/V1r4l3xpl017), [miguelmoraesx](https://github.com/miguelmoraesx), Carlos Tuma, Smith Braz |
| **Vendor**            | modified-shop.org                                                                                                           |
| **Status**            | Draft — pending vendor report                                                                                               |
| **Disclosure Date**   | TBD                                                                                                                         |

---

## Summary

> The `admin/parcel_carriers.php` page fails do sanitize the `carrier_name` and `carrier_tracking_link` fields before rendering them back to the admin UI, allowing an authenticated admin user with access to this page to store a persistent XSS payload which executes in the browser of any other administrator who views the the carriers listings or an order detail page. 

---

## Affected Component

- **File(s):** `admin/parcel_carriers.php`, `admin/orders.php`
- **Function(s) / Endpoint(s):** POST `?action=insert` ,  POST `?action=save`
- **Parameter(s):** `carrier_name`, `carrier_tracking_link`

---

## Vulnerability Details

### Root Cause

User input is persisted via `xtc_db_prepare_input()`, which only performs `trim()` + `stripslashes()` , without HTML encoding.

#### Inserting (`insert`) and Editing (`save`) Carrier

**Source (attacker-controlled input from `carrier_name` and `carrier_tracking_link`):**
```php
// admin/parcel_carriers.php:24-25
$carrier_name = xtc_db_prepare_input($_POST['carrier_name']);
$carrier_tracking_link = xtc_db_prepare_input($_POST['carrier_tracking_link']);
```

The values then are added to an array, that will be passed on to `xtc_db_perform` function for persistence. The inputs are received via POST request.

The same treatment is made when editing a carrier (lines 39-40)

**Sink #1 — listing of carriers**
```php
// admin/parcel_carriers.php:112-113
<td class="dataTableContent"><?php echo $carriers['carrier_name']; ?></td>
<td class="dataTableContent"><?php echo $carriers['carrier_tracking_link']; ?></td>
```

**Sink #2 — infobox title and content, rendered without encoding**
```php
// admin/parcel_carriers.php: 169 and 173 --- arrays used for rendering infobox without escape 
$heading[] = array('text' => '<b>' . $cInfo->carrier_name . '</b>');
// ...
$contents[] = array('text' => '<br />' . TEXT_INFO_CARRIER_NAME . '<br />' . $cInfo->carrier_name);

```

The `admin/includes/classes/box.php` renders the unsanitized `carrier_name` twice (heading and content). 

**Sink #3 —order detail page, by `order_info_block.php` inclusion**
```php
// admin/includes/modules/orders_info_blocks.php: 392
<td class="smallText" align="center"><?php echo $tracking['carrier_name']; ?></td>
```
### Preconditions

-  **Authentication required*** — a session with **admin** role and permissions to access and modify the carriers
- **Access to the carriers page** — the session should have access to the feature

---
## Proof of Concept

### Environment

- Target: v3.3.0, running on `http://127.0.0.1:8080` via Docker containers
- Authenticated as: **admin** user with access to `admin/parcel_carriers.php` or `admin/orders.php` page

### Steps to Reproduce

1. Authenticate as `admin` and obtain a valid session cookie (`MODsid`).
2. Navigate to `/admin/parcel_carriers.php?page=1&action=new` for creation of a new carrier
3. Send the following request:

```bash
curl -i 'http://127.0.0.1:8080/admin/parcel_carriers.php?page=1&action=insert' \
-H 'Cookie: MODsid=<session-id>' \
--data-urlencode 'carrier_name=XSSTEST2<script>alert("NAME XSS -> " + document.domain)</script>' \
--data-urlencode 'carrier_tracking_link=https://carrier.test</td><script>alert("TRACK URL XSS")</script>' \
--data-urlencode  'carrier_sort_order=1'
```

In the browser, it should look like this

![Carrier creation form containing the stored XSS payload](images/Pasted%20image%2020261111152133.png)

3. After inserting, navigate to `/admin/parcel_carriers.php`. If done through the browser, it should be automatic.
4. Observe the payload executing in the page context. (Sinks 1 and 2)
	1. The name payload triggers three times (highlighted below) when the carrier is selected (one when not), while the tracker url triggers once (on the table column)
![Stored XSS executing on the parcel carriers page](images/Pasted%20image%2020261111153528.png)

5. Navigate to `/admin/orders.php`. Select any order listed, or any order from any user.
6. Observe the payload executing by the `Shipping` selector (Sink 3)

![Stored XSS executing on the order details page](images/Pasted%20image%2020261111153918.png)

---

## Impact

- An attacker in control of a compromised admin account could create or edit already configured carrier names or tracking url to inject a stored XSS, leading to execution of arbitrary JavaScript in the browser session of any other user who renders the unsanitized data.
- Because the entry is stored, the payload persists in the database until the record is edited or deleted. The payload triggers without further attacker interaction.
 - Severity is reduced by the need for an authenticated admin session with access to this specific page; this is not exploitable by an anonymous or unauthenticated user. On instances with `CSRF_TOKEN_SYSTEM` enabled, cross-site delivery of the storing request would additionally require defeating (or already holding) a valid CSRF token.
 - Not verified, but worth checking by the vendor/tester: whether `carrier_name`/`carrier_tracking_link` are also surfaced on the storefront . If so, customer impact would need a separate assessment.
---

## Suggested Remediation

### 1. Apply HTML encoding when rendering inputs

```php
// admin/parcel_carriers.php:112-113
<td class="dataTableContent"><?php echo encode_htmlentities($carriers['carrier_name']); ?></td>
<td class="dataTableContent"><?php echo encode_htmlentities($carriers['carrier_tracking_link']); ?></td>
```

Apply the same treatment to the `infoBox` content and heading

### 2.  UTF-8 Encode the order detail info block

```php
// admin/includes/modules/orders_info_blocks.php: 392
<td class="smallText" align="center"><?php 
	htmlspecialchars(
	    $carriers['carrier_name'],
	    ENT_QUOTES | ENT_SUBSTITUTE,
	    'UTF-8'
	)
?></td>
```

The `order_info_block.php` does not explicit includes `application_top.php`, thus not directly imports the `encode_htmlentities()` function. 

`htmlspecialchars` will encode quotes and replace invalid code unit sequences with UTF-8 Unicode Replacement Character `U+FFFD`, disabling the payload. 

---

## Timeline

| Date       | Event                                                                |
| ---------- | -------------------------------------------------------------------- |
| 2026-11-11 | Vulnerability discovered and validated locally (Static review + PoC) |
| 2026-11-12 | Reported to vendor                                                   |
| YYYY-MM-DD | Vendor acknowledged                                                  |
| YYYY-MM-DD | Fix released                                                         |
| YYYY-MM-DD | Public disclosure                                                    |

---

## Credits

- [V1r4l3xpl017](https://github.com/V1r4l3xpl017)
- [miguelmoraesx](https://github.com/miguelmoraesx)
- Carlos Tuma  
- Smith Braz  

---
