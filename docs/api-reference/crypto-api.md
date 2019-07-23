Crypto API Reference
====================

Table of Contents
-----------------

<!--lint disable list-item-spacing-->

- [Namespace](#namespace)
- [`Crypto` Class](#crypto-class)
  - [`$algorithms` Property](#algorithms-property)
  - [`calculateMac($type, $credentials, $options)`](#calculatemactype-credentials-options)
    - [`calculateMac` Parameters](#calculatemac-parameters)
  - [`generateNormalizedString($type, $options)`](#generatenormalizedstringtype-options)
    - [`generateNormalizedString` Parameters](#generatenormalizedstring-parameters)
  - [`calculatePayloadHash($payload, $algorithm, $contentType)`](#calculatepayloadhashpayload-algorithm-contenttype)
    - [`calculatePayloadHash` Parameters](#calculatepayloadhash-parameters)
  - [`calculateTsMac($ts, $credentials)`](#calculatetsmacts-credentials)
    - [`calculateTsMac` Parameters](#calculatetsmac-parameters)
  - [`timestampMessage($credentials, $localtimeOffsetMsec)`](#timestampmessagecredentials-localtimeoffsetmsec)
    - [`timestampMessage` Parameters](#timestampmessage-parameters)

Namespace
---------

All classes and sub-namespaces are within the `Shawm11\Hawk\Crypto` namespace.

`Crypto` Class
--------------

Contains helper functions for various cryptographic operations.

### `$algorithms` Property

Supported HMAC algorithms. The algorithms supported by default are SHA-1
(`sha1`) and SHA-256 (`sha256`).

### `calculateMac($type, $credentials, $options)`

Calculate the HMAC digest using the given credentials.

Returns the HMAC digest as a string.

#### `calculateMac` Parameters

1. _string_ `$type` — (Optional) Indicates the purpose of the MAC.'
   'Examples: `header`, `response`, `bewit`, `message`
1. _array_ `$credentials` — (Required) Client's Hawk credentials, which include
   the following:
   - _string_ `key` — (Required) Secret key for the client
   - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be an
     algorithm in the [`$algorithms` array property](#algorithms-property).
1. _array_ `$options` — (Required) Components used to construct used to create
   the HMAC digest. It contains the following:
   - _string_ `method` — (Optional) Request method
   - _string_ `host` — (Optional) Request host
   - _string_ `port` — (Optional) Request port
   - _string_ `resource` — (Optional) URL of the request relative to the host
   - _string_ `ts` — (Optional) Timestamp (milliseconds since Jan. 1, 1970)
   - _string_ `nonce` — (Optional) Nonce used to create the `mac`
   - _string_ `hash` — (Optional) Payload hash. For payload validation only.
   - _string_ `ext` — (Optional) Extra application-specific data
   - _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
   - _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/shawm11/oz-auth-php).

### `generateNormalizedString($type, $options)`

Create a normalized Hawk string that contains the given type and options.

Returns the normalized Hawk string.

#### `generateNormalizedString` Parameters

1. _string_ `$type` — (Optional) Indicates the purpose of the MAC.
   Examples: `header`, `response`, `bewit`, `message`
1. _array_ `$options` — (Required) Components used to construct used to create
   the HMAC digest. It contains the following:
   - _string_ `method` — (Optional) Request method
   - _string_ `host` — (Optional) Request host
   - _string_ `port` — (Optional) Request port
   - _string_ `resource` — (Optional) URL of the request relative to the host
   - _string_ `ts` — (Optional) Timestamp (milliseconds since Jan. 1, 1970)
   - _string_ `nonce` — (Optional) Nonce used to create the `mac`
   - _string_ `hash` — (Optional) Payload hash. For payload validation only.
   - _string_ `ext` — (Optional) Extra application-specific data
   - _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
   - _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/shawm11/oz-auth-php).

### `calculatePayloadHash($payload, $algorithm, $contentType)`

Calculate the hash of the given payload and content type.

Returns the hash as a string.

#### `calculatePayloadHash` Parameters

1. _string_ `$payload` — (Required) Request body (or "payload")
1. _string_ `$algorithm` — (Required) Algorithm to be used for HMAC. Must be an
   algorithm in the [`$algorithms` array property](#algorithms-property).
1. _string_ `$contentType` — (Optional) Value of the `Content-Type` header in
   the request

### `calculateTsMac($ts, $credentials)`

Calculate the HMAC digest of the given timestamp using the given credentials.

Returns the HMAC digest as a string.

#### `calculateTsMac` Parameters

1. _string_ or _float_ `$ts` — (Required) Timestamp (as milliseconds since
   January 1, 1970) for which to calculate the MAC
1. _array_ `$credentials` — (Required) Client's Hawk credentials, which include
   the following:
   - _string_ `key` — (Required) Secret key for the client
   - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be an
     algorithm in the [`$algorithms` array property](#algorithms-property).

### `timestampMessage($credentials, $localtimeOffsetMsec)`

Get the current time and calculate its HMAC using the given credentials.

Return an array that contains the following:

- _float_ `ts` — Current time (as seconds since January 1, 1970)
- _string_ `tsm` — HMAC of the current time (`ts`)

#### `timestampMessage` Parameters

1. _array_ `$credentials` — (Required) Client's Hawk credentials, which include
   the following:
   - _string_ `key` — (Required) Secret key for the client
   - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be an
     algorithm in the [`$algorithms` array property](#algorithms-property).
1. _float_ `$localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
   milliseconds) of the local time

<!--lint enable list-item-spacing-->
