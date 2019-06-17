Utils API Reference
===================

Table of Contents
-----------------

<!--lint disable list-item-spacing-->

- [Namespace](#namespace)
- [`Utils` Class](#utils-class)
  - [`$limits` Property](#limits-property)
  - [`parseContentType($header)`](#parsecontenttypeheader)
    - [`parseContentType` Parameters](#parsecontenttype-parameters)
  - [`now($localtimeOffsetMsec)`](#nowlocaltimeoffsetmsec)
    - [`now` Parameters](#now-parameters)
  - [`nowSecs($localtimeOffsetMsec)`](#nowsecslocaltimeoffsetmsec)
    - [`nowSecs` Parameters](#nowsecs-parameters)
  - [`parseAuthorizationHeader($header, $keys)`](#parseauthorizationheaderheader-keys)
    - [`parseAuthorizationHeader` Parameters](#parseauthorizationheader-parameters)
  - [`escapeHeaderAttribute($attribute)`](#escapeheaderattributeattribute)
    - [`escapeHeaderAttribute` Parameters](#escapeheaderattribute-parameters)
  - [`base64urlEncode($data)`](#base64urlencodedata)
    - [`base64urlEncode` Parameters](#base64urlencode-parameters)
  - [`base64urlDecode($data)`](#base64urldecodedata)
    - [`base64urlDecode` Parameters](#base64urldecode-parameters)

Namespace
---------

All classes and sub-namespaces are within the `Shawm11\Hawk\Utils` namespace.

`Utils` Class
-------------

Contains helper functions that are _not_ cryptographic operations.

### `$limits` Property

An array that contains the limit of the length of URIs and headers to avoid a
DoS attack on string matching.

### `parseContentType($header)`

Parse `Content-Type` HTTP header content.

Returns the content type as a string.

#### `parseContentType` Parameters

1. _string_ `$header` — (Optional) Value of the `Content-Type` HTTP header

### `now($localtimeOffsetMsec)`

Get the current time with the local time offset in milliseconds.

Returns the local time (as milliseconds since January 1, 1970) with the offset
as a float.

#### `now` Parameters

1. _float_ `$localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
   milliseconds) of the local time

### `nowSecs($localtimeOffsetMsec)`

Get the current time with the local time offset in seconds.

Returns the local time (as seconds since January 1, 1970) with the offset as a
float.

#### `nowSecs` Parameters

1. _float_ `$localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
   milliseconds) of the local time

### `parseAuthorizationHeader($header, $keys)`

Parse Hawk HTTP `Authorization` header.

Returns an array that contains the header attributes and their values.

#### `parseAuthorizationHeader` Parameters

1. _string_ `$header` — (Required) Value of the `Authorization` HTTP header
1. _array_ `$keys` — (Optional, default: `id`, `ts`, `nonce`, `hash`, `ext`,
   `mac`, `app`, `dlg`) Names of the attributes the Hawk `Authorization` HTTP
   header is supposed to contain

### `escapeHeaderAttribute($attribute)`

Escape the given attribute value for use in HTTP header.

Returns the scaped attribute value as a string.

#### `escapeHeaderAttribute` Parameters

1. _string_ `$attribute` — (Required) Single header attribute value to escape

### `base64urlEncode($data)`

Encode the data given into a URL-safe Base64 encoded string. Follows RFC 4648.

Returns the Base64 encoded string.

#### `base64urlEncode` Parameters

1. _string_ `$data` — (Required) The data to encode into a URL-safe Base64
   string

### `base64urlDecode($data)`

Decode the given URL-safe Base64 string. Follows RFC 4648.

#### `base64urlDecode` Parameters

1. _string_ `$data` — (Required) URL-safe Base64 string to decode

<!--lint enable list-item-spacing-->
