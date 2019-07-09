Server API Reference
====================

Table of Contents
-----------------

<!--lint disable list-item-spacing-->

- [Namespace](#namespace)
- [`Server` Class](#server-class)
  - [`authenticate($request, $credentialsFunc, $options)`](#authenticaterequest-credentialsfunc-options)
    - [`authenticate` (`Server` Class) Parameters](#authenticate-server-class-parameters)
  - [`authenticatePayload($payload, $credentials, $artifacts, $contentType)`](#authenticatepayloadpayload-credentials-artifacts-contenttype)
    - [`authenticatePayload` Parameters](#authenticatepayload-parameters)
  - [`authenticatePayloadHash($calculatedHash, $artifacts)`](#authenticatepayloadhashcalculatedhash-artifacts)
    - [`authenticatePayloadHash` Parameters](#authenticatepayloadhash-parameters)
  - [`header($credentials, $artifacts, $options)`](#headercredentials-artifacts-options)
    - [`header` (`Server` Class) Parameters](#header-server-class-parameters)
  - [`authenticateBewit($request, $credentialsFunc, $options)`](#authenticatebewitrequest-credentialsfunc-options)
    - [`authenticateBewit` Parameters](#authenticatebewit-parameters)
  - [`authenticateMessage($host, $port, $message, $authorization, $credentialsFunc, $options)`](#authenticatemessagehost-port-message-authorization-credentialsfunc-options)
    - [`authenticateMessage` Parameters](#authenticatemessage-parameters)
- [`ServerException` Class](#serverexception-class)
- [`BadRequestException` Class](#badrequestexception-class)
  - [`getCode()` (`BadRequestException` Class)](#getcode-badrequestexception-class)
  - [`getMessage()` (`BadRequestException` Class)](#getmessage-badrequestexception-class)
- [`UnauthorizedException` Class](#unauthorizedexception-class)
  - [`getCode()` (`UnauthorizedException` Class)](#getcode-unauthorizedexception-class)
  - [`getMessage()` (`UnauthorizedException` Class)](#getmessage-unauthorizedexception-class)
  - [`getWwwAuthenticateHeaderAttributes()`](#getwwwauthenticateheaderattributes)
  - [`getWwwAuthenticateHeader()`](#getwwwauthenticateheader)

Namespace
---------

All classes and sub-namespaces are within the `Shawm11\Hawk\Server` namespace.

`Server` Class
--------------

Contains methods for the server, which receives client requests. The server
usually is the system that stores and manages user credentials and data.

<!--lint disable maximum-heading-length-->

### `authenticate($request, $credentialsFunc, $options)`

Validate the given request from a client.

Returns an array that contains the following if there were no errors:

- _array_ `credentials` — Client's Hawk credentials, which include the
  following:
  - _string_ `key` — Secret key for the client
  - _string_ `algorithm` — Algorithm to be used for HMAC. Must be an algorithm
    in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
- _array_ `artifacts` — Components of the request including the `Authorization`
  HTTP header. It includes the following:
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
  - _string_ `mac` — HMAC digest of the other items in this array
  - _string_ `id` — Client's unique Hawk ID

#### `authenticate` (`Server` Class) Parameters

1. _array_ `$request` — (Required) Request data. Contains the following:
   - _string_ `method` — (Required) HTTP method of the request
   - _string_ `url` — (Optional) URL (without the host and port) the request
     was sent to
   - _string_ `host` — (Required) Host of the server the request was sent to
     (e.g. example.com)
   - _integer_ `port` — (Required) Port number the request was sent to
   - _string_ `authorization` — (Optional) Value of the `Authorization`
     header in the request. See [`header()` for the `Client` class](client-api.md#headeruri-method-options).
   - _string_ `contentType` — (Optional) Payload content type. It is usually
     the value of the `Content-Type` header in the request. Only used for
     payload validation.
1. _callable_ `$credentialsFunc` — (Required) Function for looking up the set
   of Hawk credentials based on the provided credentials ID. The function must
   have the following:
   - Parameter: _string_ `$id` — (Required) Unique ID for the client used to
     look up the client's set of credentials.
   - Returns: _array_ — (Required) Set of credentials that contains the
     following:
     - _string_ `key` — (Required) Secret key for the client
     - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
       an algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
1. _array_ `$options` — (Optional) Includes the following:
   - _string_ `host` — (Optional) Host of the server (e.g. example.com).
     Overrides the `host` in the `$request` parameter.
   - _integer_ `port` — (Optional) Port number. Overrides the `port` in the
     `$request` parameter.
   - _integer_ `timestampSkewSec` — (Optional, default: `60`) Amount of time (in
     seconds) the client and server timestamps can differ (usually because of
     network latency)
   - _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
     milliseconds) of the server's local time compared to the client's local
     time
   - _string_ `payload` — (Optional) Request body (or "payload"). Only used for
     payload validation.
   - _callable_ `nonceFunc` — (Optional) Function for checking the generated
     nonce (**n**umber used **once**) that is used to make the MAC unique even
     if given the same data. It must throw an error if the nonce check fails.

### `authenticatePayload($payload, $credentials, $artifacts, $contentType)`

Authenticate payload hash using the payload, credentials, content type to
calculate the hash. Only used when payload cannot be provided during
[`authenticate()`](#authenticaterequest-credentialsFunc-options).

#### `authenticatePayload` Parameters

1. _string_ `$payload` — (Required) Request body (or "payload")
1. _array_ `$credentials` — (Required) Set of credentials that contains the
   following:
   - _string_ `key` — (Required) Secret key for the client
   - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be an
     algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
1. _array_ `$artifacts` — (Required) Contains the following:
   - _string_ `hash` — (Required) Payload hash
1. _string_ `$contentType` — (Optional) Value of the `Content-Type` header in
   the request

### `authenticatePayloadHash($calculatedHash, $artifacts)`

Authenticate payload hash using the given pre-calculated hash. Only used when
payload cannot be provided when using [`authenticate()`](#authenticaterequest-credentialsFunc-options).

#### `authenticatePayloadHash` Parameters

1. _string_ `$calculatedHash` — (Required) Pre-calculated payload hash
1. _array_ `$artifacts` — (Required) Contains the following:
   - _string_ `hash` — (Required) Payload hash

### `header($credentials, $artifacts, $options)`

Generate the value for the `Server-Authorization` HTTP header for the given
response (response data contained in the `$artifacts`).

Returns the value for the `Server-Authorization` header (as a string) for the
server's response.

#### `header` (`Server` Class) Parameters

1. _array_ `$credentials` — (Required) Set of credentials that contains the
   following:
   - _string_ `key` — (Required) Secret key for the client
   - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be an
     algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
1. _array_ `$artifacts` — (Required) Components to be used to construct the
   response `Server-Authorization` HTTP header. It includes the following:
   - _string_ `method` — Request method
   - _string_ `host` — Request host
   - _string_ `port` — Request port
   - _string_ `resource` — URL of the request relative to the host
   - _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
   - _string_ `nonce` — Nonce used to create the `mac`
   - _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
   - _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/shawm11/oz-auth-php).
   - _string_ `id` — Client's unique Hawk ID
1. _array_ `$options` — (Optional) Hawk attributes that will be integrated into
   the `Server-Authorization` header value. It includes the following:
   - _string_ `hash` — (Optional) Payload hash. Only used for payload
     validation
   - _string_ `contentType` — (Optional) Payload content type. It is usually the
     value of the `Content-Type` header in the request. Only used for payload
     validation.
   - _string_ `payload` — (Optional) Request body (or "payload").
     Only used for payload validation.
   - _string_ `ext` — (Optional) Extra application-specific data

### `authenticateBewit($request, $credentialsFunc, $options)`

Validate the bewit contained in the given request URL.

Returns and array that includes the following (if the bewit is valid):

- _array_ `credentials` — Client's Hawk credentials, which include the
  following:
  - _string_ `key` — Secret key for the client
  - _string_ `algorithm` — Algorithm to be used for HMAC. Must be an
    algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
- _array_ `artifacts` — Components of the bewit, which include the following:
  - _string_ `id` — Client ID
  - _string_ `exp` — Timestamp (as milliseconds since January 1, 1970) of when
    the bewit expires
  - _string_ `mac` — Bewit HMAC
  - _string_ `ext` — Extra application-specific data

#### `authenticateBewit` Parameters

1. _array_ `$request` — (Required) Request data. Contains the following:
   - _string_ `method` — (Required) HTTP method of the request
   - _string_ `url` — (Optional) URL (without the host and port) the request was
     sent to
   - _string_ `host` — (Required) Host of the server the request was sent to
     (e.g. example.com)
   - _integer_ `port` — (Required) Port number the request was sent to
   - _string_ `authorization` — (Optional) Value of the `Authorization`
     header in the request. See [`header()` for the `Client` class](client-api.md#headeruri-method-options).
   - _string_ `contentType` — (Optional) Payload content type. It is usually the
     value of the `Content-Type` header in the request. Only used for payload
     validation.
1. _callable_ `$credentialsFunc` — (Required) Function for looking up the set
   of Hawk credentials based on the provided credentials ID. The function must
   have the following:
   - Parameter: _string_ `$id` — (Required) Unique ID for the client used to
     look up the client's set of credentials.
   - Returns: _array_ — (Required) Set of credentials that contains the
     following:
     - _string_ `key` — (Required) Secret key for the client
     - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
       an algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
1. _array_ `$options` — (Optional) Includes the following:
   - _string_ `host` — (Optional) Host of the server (e.g. example.com).
     Overrides the `host` in the `$request` parameter.
   - _integer_ `port` — (Optional) Port number. Overrides the `port` in the
     `$request` parameter.
   - _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
     milliseconds) of the server's local time compared to the client's local
     time

### `authenticateMessage($host, $port, $message, $authorization, $credentialsFunc, $options)`

Validate the given message against the given authorization string.

Returns and array that includes the following (if the message is valid):

- _array_ `credentials` — Client's Hawk credentials, which include the
  following:
  - _string_ `key` — Secret key for the client
  - _string_ `algorithm` — Algorithm to be used for HMAC. Must be an algorithm
    in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).

#### `authenticateMessage` Parameters

1. _string_ `$host` — (Required) Host of the server the request was sent to
    (e.g. example.com)
1. _integer_ `$port` — (Required) Port number the request was sent to
1. _string_ `$message` — (Required) Message to validate
1. _string_  `$authorization` — (Required) Components used to create
   authorization string for the message. See [`message()` in the `Client` class](client-api.md#messagehost-port-message-options)
1. _callable_ `$credentialsFunc` — (Required) Function for looking up the set of
   Hawk credentials based on the provided credentials ID. The function must
   have the following:
   - Parameter: _string_ `$id` — (Required) Unique ID for the client used to
     look up the client's set of credentials.
   - Returns: _array_ — (Required) Set of credentials that contains the
     following:
     - _string_ `key` — (Required) Secret key for the client
     - _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
       an algorithm in the [`$algorithms` array property of the `Crypto` class](crypto.md#algorithms-property).
1. _array_ `$options` — (Optional) Includes the following:
   - _integer_ `timestampSkewSec` — (Optional, default: `60`) Amount of time
     (in seconds) the client and server timestamps can differ (usually because
     of network latency)
   - _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
     milliseconds) of the server's local time compared to the client's local
     time
   - _callable_ `nonceFunc` — (Optional) Function for checking the generated
     nonce (**n**umber used **once**) that is used to make the MAC unique
     even if given the same data. It must throw an error if the nonce check
     fails.

`ServerException` Class
-----------------------

The exception that is thrown when there is a _server_ Hawk error.

`BadRequestException` Class
---------------------------

A type of `ServerException` exception that represents an HTTP `400 Bad Request`
server response.

### `getCode()` (`BadRequestException` Class)

Inherited method from PHP's `Exception` class. Gives HTTP status code, which is
always `400`, as an integer.

### `getMessage()` (`BadRequestException` Class)

Inherited method from PHP's `Exception` class. Gives the error message text.

`UnauthorizedException` Class
-----------------------------

A type of `ServerException` exception that represents an HTTP `401 Unauthorized`
server response.

### `getCode()` (`UnauthorizedException` Class)

Inherited method from PHP's `Exception` class. Gives HTTP status code, which is
always `401`, as an integer.

### `getMessage()` (`UnauthorizedException` Class)

Inherited method from PHP's `Exception` class. Gives the error message text.

### `getWwwAuthenticateHeaderAttributes()`

Get the associative array of keys and values included in the HTTP
`WWW-Authenticate` header should be set to in the server's response.

### `getWwwAuthenticateHeader()`

Get the value the HTTP `WWW-Authenticate` header should be set to in the
server's response.

<!--lint enable maximum-heading-length-->

<!--lint enable list-item-spacing-->
