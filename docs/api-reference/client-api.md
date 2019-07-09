Client API Reference
====================

Table of Contents
-----------------

<!--lint disable list-item-spacing-->

- [Namespace](#namespace)
- [`Client` Class](#client-class)
  - [`header($uri, $method, $options)`](#headeruri-method-options)
    - [`header` (`Client` Class) Parameters](#header-client-class-parameters)
  - [`authenticate($responseHeaders, $credentials, $artifacts, $options)`](#authenticateresponseheaders-credentials-artifacts-options)
    - [`authenticate` (`Client` Class) Parameters](#authenticate-client-class-parameters)
  - [`getBewit($uri, $method, $options)`](#getbewituri-method-options)
    - [`getBewit` Parameters](#getbewit-parameters)
  - [`message($host, $port, $message, $options)`](#messagehost-port-message-options)
    - [`message` Parameters](#message-parameters)
- [`ClientException` Class](#clientexception-class)

Namespace
---------

All classes and sub-namespaces are within the `Shawm11\Hawk\Client` namespace.

`Client` Class
--------------

Contains methods for the client, which makes requests to the server.

### `header($uri, $method, $options)`

Generate the value for an HTTP `Authorization` header for a request to the
server.

Returns an array that contains the following:

- _string_ `header` — Value for the `Authorization` header for the client's
  request to the server.
- _array_ `artifacts` — Components used to construct the request including the
  `Authorization` HTTP header. It includes the following:
  - _string_ `method` — Request method
  - _string_ `host` — Request host
  - _string_ `port` — Request port
  - _string_ `resource` — URL of the request relative to the host
  - _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
  - _string_ `nonce` — Nonce used to create the `mac`
  - _string_ `hash` — Payload hash. Only used for payload validation.
  - _string_ `ext` — Extra application-specific data
  - _string_ `app` — Application ID. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
  - _string_ `dlg` — 'delegated-by' attribute. Only used with [Oz](https://github.com/shawm11/oz-auth-php).

#### `header` (`Client` Class) Parameters

1. _string_ or _array_ `$uri` — (Required) URI (as a string) of the request or
   an array that is the output of PHP's `parse_url()`
1. _string_ `$method` — (Required) HTTP verb of the request (e.g. `GET`,
   `POST`)
1. _array_ `$options` — (Required) Hawk attributes that will be integrated into
   the `Authorization` header value. It includes the following:
   - _array_ `credentials` — (Required) Client's Hawk credentials, which include
     the following:
     - _string_ `id` — (Required) Client's unique Hawk ID
     - _string_ `key` — (Required) Secret key for the client
     - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
       an algorithm in the [`$algorithms` array property of the `Crypto` class](cypto-api.md#algorithms-property).
   - _float_ `timestamp` — (Optional) Timestamp (as milliseconds since
     January 1, 1970)
   - _string_ `nonce` — (Optional) Nonce to be used to create the HMAC
   - _string_ `hash` — (Optional) Payload hash. Only used for payload
     validation.
   - _string_ `payload` — (Optional) Request body (or "payload"). Only used for
     payload validation.
   - _string_ `contentType` — (Optional) Payload content type. It is usually the
     value of the `Content-Type` header in the request. Only used for payload
     validation.
   - _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
     milliseconds) of the client's local time compared to the server's local
     time
   - _string_ `ext` — (Optional) Extra application-specific data
   - _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
   - _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/shawm11/oz-auth-php).

<!--lint disable maximum-heading-length-->

### `authenticate($responseHeaders, $credentials, $artifacts, $options)`

<!--lint disable maximum-heading-length-->

Validate the server's response.

#### `authenticate` (`Client` Class) Parameters

1. _array_ `$responseHeaders` — (Required if `$options['required']` is `true`)
   HTTP headers from the server's response. May contain the following:
   - `WWW-Authenticate` — (Required if `$options['required']` is `true`) Only
     set when the server's response is an HTTP `401 Unauthorized` response
   - `Server-Authorization` — (Optional) Used to verify that the client is
     communicating with the correct server. Uses the same syntax as the
     `Authorization` header in the client's request.
   - `Content-Type` — (Optional) Only used for payload validation.
1. _array_ `$credentials` — (Required) Client's Hawk credentials, which include
   the following:
   - _string_ `id` — (Required) Client's unique Hawk ID
   - _string_ `key` — (Required) Secret key for the client
   - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be an
     algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
1. _array_ `$artifacts` — (Required) Components used to construct the request
   including the `Authorization` HTTP header. It includes the following:
   - _string_ `method` — Request method
   - _string_ `host` — Request host
   - _string_ `port` — Request port
   - _string_ `resource` — URL of the request relative to the host
   - _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
   - _string_ `nonce` — Nonce used to create the `mac`
   - _string_ `hash` — Payload hash. Only used for payload validation.
   - _string_ `ext` — Extra application-specific data
   - _string_ `app` — Application ID. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
   - _string_ `dlg` — 'delegated-by' attribute. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
1. _array_ `$options` — (Optional) Includes the following:
   - _string_ `payload` — (Optional) Request body (or "payload"). Only used for
     payload validation.
   - _boolean_ `required` — (Optional, default: `false`) If server's response
     must contain the `Server-Authorization` HTTP header (must be included in
     `$requestHeaders`)

### `getBewit($uri, $method, $options)`

Generate a bewit value for the given URI.

Returns the bewit as a string.

#### `getBewit` Parameters

1. _string_ or _array_ `$uri` — (Required) URI (as a string) for which to
   generate the bewit or an array that is the output of PHP's `parse_url()`
1. _array_ `$options` — (Required) Items used to create the bewit. Includes the
   following:
   - _array_ `credentials` — (Required) Client's Hawk credentials, which include
     the following:
     - _string_ `id` — (Required) Client's unique Hawk ID
     - _string_ `key` — (Required) Secret key for the client
     - _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
       Must be an algorithm in the [`$algorithms` array property of the `Crypto`
       class](crypto.md#algorithms-property).
   - _integer_ `ttlSec` — (Required) Amount of time (in seconds) the bewit is
     valid
   - _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
     milliseconds) of the client's local time compared to the server's local
     time
   - _string_ `ext` — (Optional) Extra application-specific data

### `message($host, $port, $message, $options)`

Generate an authorization string for the given message.

Returns an array that contains the following:

- _string_ `id` — Client's unique Hawk ID
- _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
- _string_ `nonce` — Nonce used to create the `mac`
- _string_ `hash` — Payload hash. Only used for payload validation.
- _string_ `mac` — Authorization string for the message

#### `message` Parameters

1. _string_ `$host` — (Required) Host portion of the URI the message will be
   sent to (e.g. example.com)
1. _integer_ `$port` — (Required) Port number of the URI the message will be
   sent to
1. _string_ `$message` — (Required) Message for which to generate an
   authorization
1. _array_ `$options` — (Optional) Includes the following:
   - _array_ `credentials` — (Required) Client's Hawk credentials, which include
     the following:
     - _string_ `id` — (Required) Client's unique Hawk ID
     - _string_ `key` — (Required) Secret key for the client
     - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
       an algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
   - _float_ `timestamp` — (Optional) Timestamp (as milliseconds since
     January 1, 1970)
   - _string_ `nonce` — (Optional) Nonce to be used to create the HMAC of the
     message
   - _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
     milliseconds) of the client's local time compared to the server's local

`ClientException` Class
-----------------------

The exception that is thrown when there is a _client_ Hawk error.

<!--lint enable list-item-spacing-->
