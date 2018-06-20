API Reference
=============

Table of Contents
-----------------

-   [Namespace](#namespace)

-   [`Server\Server` Class](#serverserver-class)
    -   [`authenticate($request, $credentialsFunc, $options)`](#authenticaterequest-credentialsFunc-options)
        - [`authenticate` (`Server` Class) Parameters](#authenticate-server-class-parameters)

    -   [`authenticatePayload($payload, $credentials, $artifacts, $contentType)`](#authenticatepayloadpayload-credentials-artifacts-contenttype`)
        - [`authenticatePayload` Parameters](#authenticatepayload-parameters)

    -   [`authenticatePayloadHash($calculatedHash, $artifacts)`](#authenticatepayloadhashcalculatedhash-artifacts`)
        - [`authenticatePayloadHash` Parameters](#authenticatepayloadhash-parameters)

    -   [`header($credentials, $artifacts, $options)`](#headercredentials-artifacts-options)
        - [`header` (`Server` Class) Parameters](#header-server-class-parameters)

    -   [`authenticateBewit($request, $credentialsFunc, $options)`](#authenticatebewitrequest-credentialsfunc-options)
        - [`authenticateBewit` Parameters](#authenticatebewit-parameters)

    -   [`authenticateMessage($host, $port, $message, $authorization, $credentialsFunc, $options)`](#authenticatemessagehost-port-message-authorization-credentialsfunc-options)
        - [`authenticateMessage` Parameters](#authenticatemessage-parameters)

-   [`Server\ServerException` Class](#serverserverexception-class)

-   [`Server\BadRequestException` Class](#serverbadrequestexception-class)
    - [`getCode()` (`BadRequestException` Class)](#getcode-badrequestexception-class)
    - [`getMessage()` (`BadRequestException` Class)](#getmessage-badrequestexception-class)

-   [`Server\UnauthorizedException` Class](#serverunauthorizedexception-class)
    - [`getCode()` (`UnauthorizedException` Class)](#getcode-unauthorizedexception-class)
    - [`getMessage()` (`UnauthorizedException` Class)](#getmessage-unauthorizedexception-class)
    - [`getWwwAuthenticateHeaderAttributes()`](#getwwwauthenticateheaderattributes)
    - [`getWwwAuthenticateHeader()`](#getwwwauthenticateheader)

-   [`Client\Client` Class](#clientclient-class)
    -   [`header($uri, $method, $options)`](#headeruri-method-options)
        - [`header` (`Client` Class) Parameters](#header-client-class-parameters)

    -   [`authenticate($responseHeaders, $credentials, $artifacts, $options)`](#authenticateresponseheaders-credentials-artifacts-options)
        - [`authenticate` (`Client` Class) Parameters](#authenticate-client-class-parameters)

    -   [`getBewit($uri, $method, $options)`](#getbewituri-method-options)
        - [`getBewit` Parameters](#getbewit-parameters)

    -   [`message($host, $port, $message, $options)`](#messagehost-port-message-options)
        - [`message` Parameters](#message-parameters)

-   [`Client\ClientException` Class](#clientclientexception-class)

-   [`Crypto\Crypto` Class](#cryptocrypto-class)
    -   [`$algorithms` Property](#algorithms-property)

    -   [`calculateMac($type, $credentials, $options)`](#calculatemactype-credentials-options)
        - [`calculateMac` Parameters](#calculatemac-parameters)

    -   [`generateNormalizedString($type, $options)`](#generatenormalizedstringtype-options)
        - [`generateNormalizedString` Parameters](#generatenormalizedstring-parameters)

    -   [`calculatePayloadHash($payload, $algorithm, $contentType)`](#calculatepayloadhashpayload-algorithm-contenttype)
        - [`calculatePayloadHash` Parameters](#calculatepayloadhash-parameters)

    -   [`calculateTsMac($ts, $credentials)`](#calculatetsmacts-credentials)
        - [`calculateTsMac` Parameters](#calculatetsmac-parameters)

    -   [`timestampMessage($credentials, $localtimeOffsetMsec)`](#timestampmessagecredentials-localtimeoffsetmsec)
        - [`timestampMessage` Parameters](#timestampmessage-parameters)

-   [`Utils\Utils` Class](#utilsutils-class)
    -   [`$limits` Property](#limits-property)

    -   [`parseContentType($header)`](#parsecontenttypeheader)
        - [`parseContentType` Parameters](#parsecontenttype-parameters)

    -   [`now($localtimeOffsetMsec)`](#nowlocaltimeoffsetmsec)
        - [`now` Parameters](#now-parameters)

    -   [`nowSecs($localtimeOffsetMsec)`](#nowsecslocaltimeoffsetmsec)
        - [`nowSecs` Parameters](#nowsecs-parameters)

    -   [`parseAuthorizationHeader($header, $keys)`](#parseauthorizationheaderheader-keys)
        - [`parseAuthorizationHeader` Parameters](#parseauthorizationheader-parameters)

    -   [`escapeHeaderAttribute($attribute)`](#escapeheaderattributeattribute)
        - [`escapeHeaderAttribute` Parameters](#escapeheaderattribute-parameters)

    -   [`base64urlEncode($data)`](#base64urlencodedata)
        - [`base64urlEncode` Parameters](#base64urlencode-parameters)

    -   [`base64urlDecode($data)`](#base64urldecodedata)
        - [`base64urlDecode` Parameters](#base64urldecode-parameters)

Namespace
---------

All classes and sub-namespaces are within the `Shawm11\Hawk` namespace.

`Server\Server` Class
---------------------

Contains methods for the server, which receives client requests. The server
usually is the system that stores and manages user credentials and data.

### `authenticate($request, $credentialsFunc, $options)`

Validate the given request from a client.

Returns an array that contains the following if there were no errors:

-   _array_ `credentials` — Client's Hawk credentials, which include the
    following:

    -   _string_ `key` — Secret key for the client

    -   _string_ `algorithm` — Algorithm to be used for HMAC. Must be an
        algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

-   _array_ `artifacts` — Components of the request including the
    `Authorization` HTTP header. It includes the following:

    - _string_ `method` — Request method
    - _string_ `host` — Request host
    - _string_ `port` — Request port
    - _string_ `resource` — URL of the request relative to the host
    - _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
    - _string_ `nonce` — Nonce used to create the `mac`
    - _string_ `hash` — Payload hash. Only used for payload validation.
    - _string_ `ext` — Extra application-specific data
    - _string_ `app` — Application ID. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `dlg` — 'delegated-by' attribute. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `mac` — HMAC digest of the other items in this array
    - _string_ `id` — Client's unique Hawk ID

#### `authenticate` (`Server` Class) Parameters

1.  _array_ `$request` — (Required) Request data. Contains the following:

    -   _string_ `method` — (Required) HTTP method of the request

    -   _string_ `url` — (Optional) URL (without the host and port) the request
        was sent to

    -   _string_ `host` — (Required) Host of the server the request was sent to
        (e.g. example.com)

    -   _integer_ `port` — (Required) Port number the request was sent to

    -   _string_ `authorization` — (Optional) Value of the `Authorization`
        header in the request. See [`header()` for the `Client` class](#headeruri-method-options).

    -   _string_ `contentType` — (Optional) Payload content type. It is usually
        the value of the `Content-Type` header in the request. Only used for
        payload validation.

1.  _callable_ `$credentialsFunc` — (Required) Function for looking up the set
    of Hawk credentials based on the provided credentials ID. The function must
    have the following:

    -   Parameter: _string_ `$id` — (Required) Unique ID for the client used to
        look up the client's set of credentials.

    -   Returns: _array_ — (Required) Set of credentials that contains the
        following:

        -   _string_ `key` — (Required) Secret key for the client

        -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
            Must be an algorithm in the [`$algorithms` array property of the
            `Crypto` class](#algorithms-property).

1.  _array_ `$options` — (Optional) Includes the following:

    -   _string_ `host` — (Optional) Host of the server (e.g. example.com).
        Overrides the `host` in the `$request` parameter.

    -   _integer_ `port` — (Optional) Port number. Overrides the `port` in the
        `$request` parameter.

    -   _integer_ `timestampSkewSec` — (Optional, default: `60`)
        Amount of time (in seconds) the client and server timestamps can differ
        (usually because of network latency)

    -   _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
        milliseconds) of the server's local time compared to the client's local
        time

    -   _string_ `payload` — (Optional) UTF-8-encoded request body (or
        "payload"). Only used for payload validation.

    -   _callable_ `nonceFunc` — (Optional) Function for checking the generated
        nonce (**n**umber used **once**) that is used to make the MAC unique
        even if given the same data. It must throw an error if the nonce check
        fails.

### `authenticatePayload($payload, $credentials, $artifacts, $contentType)`

Authenticate payload hash using the payload, credentials, content type to
calculate the hash. Only used when payload cannot be provided during
[`authenticate()`](#authenticaterequest-credentialsFunc-options).

#### `authenticatePayload` Parameters

1.  _string_ `$payload` — (Required) UTF-8-encoded request body (or "payload")

1.  _array_ `$credentials` — (Required) Set of credentials that contains the
    following:

    -   _string_ `key` — (Required) Secret key for the client

    -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
        Must be an algorithm in the [`$algorithms` array property of the
        `Crypto` class](#algorithms-property).

1.  _array_ `$artifacts` — (Required) Contains the following:
    - _string_ `hash` — (Required) Payload hash

1.  _string_ `$contentType` — (Optional) Value of the `Content-Type` header
    in the request

### `authenticatePayloadHash($calculatedHash, $artifacts)`

Authenticate payload hash using the given pre-calculated hash. Only used when
payload cannot be provided during
[`authenticate()`](#authenticaterequest-credentialsFunc-options).

#### `authenticatePayloadHash` Parameters

1.  _string_ `$calculatedHash` — (Required) Pre-calculated payload hash

1.  _array_ `$artifacts` — (Required) Contains the following:
    - _string_ `hash` — (Required) Payload hash

### `header($credentials, $artifacts, $options)`

Generate the value for the `Server-Authorization` HTTP header for the given
response (response data contained in the `$artifacts`).

Returns the value for the `Server-Authorization` header (as a string) for the
server's response.

#### `header` (`Server` Class) Parameters

1.  _array_ `$credentials` — (Required) Set of credentials that contains the
    following:

    -   _string_ `key` — (Required) Secret key for the client

    -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
        Must be an algorithm in the [`$algorithms` array property of the
        `Crypto` class](#algorithms-property).

1.  _array_ `$artifacts` — (Required) Components to be used to construct the
    response `Server-Authorization` HTTP header. It includes the following:

    - _string_ `method` — Request method
    - _string_ `host` — Request host
    - _string_ `port` — Request port
    - _string_ `resource` — URL of the request relative to the host
    - _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
    - _string_ `nonce` — Nonce used to create the `mac`
    - _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `id` — Client's unique Hawk ID

1.  _array_ `$options` — (Optional) Hawk attributes that will be integrated
    into the `Server-Authorization` header value. It includes the following:

    -   _string_ `hash` — (Optional) Payload hash. Only used for payload
        validation

    -   _string_ `contentType` — (Optional) Payload content type. It is usually
        the value of the `Content-Type` header in the request. Only used for
        payload validation.

    -   _string_ `payload` — (Optional) UTF-8-encoded request body (or
        "payload"). Only used for payload validation.

    -   _string_ `ext` — (Optional) Extra application-specific data

### `authenticateBewit($request, $credentialsFunc, $options)`

Validate the bewit contained in the given request URL.

Returns and array that includes the following (if the bewit is valid):

-   _array_ `credentials` — Client's Hawk credentials, which include the
    following:

    -   _string_ `key` — Secret key for the client

    -   _string_ `algorithm` — Algorithm to be used for HMAC. Must be an
        algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

-   _array_ `artifacts` — Components of the bewit, which include the following:

    -   _string_ `id` — Client ID

    -   _string_ `exp` — Timestamp (as milliseconds since January 1, 1970) of
        when the bewit expires

    -   _string_ `mac` — Bewit HMAC

    -   _string_ `ext` — Extra application-specific data

#### `authenticateBewit` Parameters

1.  _array_ `$request` — (Required) Request data. Contains the following:

    -   _string_ `method` — (Required) HTTP method of the request

    -   _string_ `url` — (Optional) URL (without the host and port) the request
        was sent to

    -   _string_ `host` — (Required) Host of the server the request was sent to
        (e.g. example.com)

    -   _integer_ `port` — (Required) Port number the request was sent to

    -   _string_ `authorization` — (Optional) Value of the `Authorization`
        header in the request. See [`header()` for the `Client` class](#headeruri-method-options).

    -   _string_ `contentType` — (Optional) Payload content type. It is usually
        the value of the `Content-Type` header in the request. Only used for
        payload validation.

1.  _callable_ `$credentialsFunc` — (Required) Function for looking up the set
    of Hawk credentials based on the provided credentials ID. The function must
    have the following:

    -   Parameter: _string_ `$id` — (Required) Unique ID for the client used to
        look up the client's set of credentials.

    -   Returns: _array_ — (Required) Set of credentials that contains the
        following:

        -   _string_ `key` — (Required) Secret key for the client

        -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
            Must be an algorithm in the [`$algorithms` array property of the
            `Crypto` class](#algorithms-property).

1.  _array_ `$options` — (Optional) Includes the following:

    -   _string_ `host` — (Optional) Host of the server (e.g. example.com).
        Overrides the `host` in the `$request` parameter.

    -   _integer_ `port` — (Optional) Port number. Overrides the `port` in the
        `$request` parameter.

    -   _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
        milliseconds) of the server's local time compared to the client's local
        time

### `authenticateMessage($host, $port, $message, $authorization, $credentialsFunc, $options)`

Validate the given message against the given authorization string.

Returns and array that includes the following (if the message is valid):

-   _array_ `credentials` — Client's Hawk credentials, which include the
    following:

    -   _string_ `key` — Secret key for the client

    -   _string_ `algorithm` — Algorithm to be used for HMAC. Must be an
        algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

#### `authenticateMessage` Parameters

1.  _string_ `$host` — (Required) Host of the server the request was sent to
    (e.g. example.com)

1.  _integer_ `$port` — (Required) Port number the request was sent to

1.  _string_ `$message` — (Required) Message to validate

1.  _string_  `$authorization` — (Required) Components used to create
    authorization string for the message. See [`message()` in the `Client` class](#messagehost-port-message-options)

1.  _callable_ `$credentialsFunc` — (Required) Function for looking up the set
    of Hawk credentials based on the provided credentials ID. The function must
    have the following:

    -   Parameter: _string_ `$id` — (Required) Unique ID for the client used to
        look up the client's set of credentials.

    -   Returns: _array_ — (Required) Set of credentials that contains the
        following:

        -   _string_ `key` — (Required) Secret key for the client

        -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
            Must be an algorithm in the [`$algorithms` array property of the
            `Crypto` class](#algorithms-property).

1.  _array_ `$options` — (Optional) Includes the following:

    -   _integer_ `timestampSkewSec` — (Optional, default: `60`) Amount of time
        (in seconds) the client and server timestamps can differ (usually
        because of network latency)

    -   _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
        milliseconds) of the server's local time compared to the client's local
        time

    -   _callable_ `nonceFunc` — (Optional) Function for checking the generated
        nonce (**n**umber used **once**) that is used to make the MAC unique
        even if given the same data. It must throw an error if the nonce check
        fails.

`Server\ServerException` Class
------------------------------

The exception that is thrown when there is a _server_ Hawk error.

`Server\BadRequestException` Class
----------------------------------

A type of `Server\ServerException` exception that represents an HTTP
`400 Bad Request` server response.

### `getCode()` (`BadRequestException` Class)

Inherited method from PHP's `Exception` class. Gives HTTP status code, which is
always `400`, as an integer.

### `getMessage()` (`BadRequestException` Class)

Inherited method from PHP's `Exception` class. Gives the error message text.

`Server\UnauthorizedException` Class
------------------------------------

A type of `Server\ServerException` exception that represents an HTTP
`401 Unauthorized` server response.

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

`Client\Client` Class
---------------------

Contains methods for the client, which makes requests to the server.

### `header($uri, $method, $options)`

Generate the value for an HTTP `Authorization` header for a request to the
server.

Returns an array that contains the following:

-   _string_ `header` — Value for the `Authorization` header for the client's
    request to the server.

-   _array_ `artifacts` — Components used to construct the request including the
    `Authorization` HTTP header. It includes the following:

    - _string_ `method` — Request method
    - _string_ `host` — Request host
    - _string_ `port` — Request port
    - _string_ `resource` — URL of the request relative to the host
    - _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
    - _string_ `nonce` — Nonce used to create the `mac`
    - _string_ `hash` — Payload hash. Only used for payload validation.
    - _string_ `ext` — Extra application-specific data
    - _string_ `app` — Application ID. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `dlg` — 'delegated-by' attribute. Only used with [Oz](https://github.com/hueniverse/oz).

#### `header` (`Client` Class) Parameters

1.  _string_ or _array_ `$uri` — (Required) URI (as a string) of the request or
    an array that is the output of PHP's `parse_url()`

1.  _string_ `$method` — (Required) HTTP verb of the request (e.g. `GET`,
    `POST`)

1.  _array_ `$options` — (Required) Hawk attributes that will be integrated
    into the `Authorization` header value. It includes the following:

    -   _array_ `credentials` — (Required) Client's Hawk credentials, which
        include the following:

        -   _string_ `id` — (Required) Client's unique Hawk ID

        -   _string_ `key` — (Required) Secret key for the client

        -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
            Must be an algorithm in the [`$algorithms` array property of the
            `Crypto` class](#algorithms-property).

    -   _float_ `timestamp` — (Optional) Timestamp (as milliseconds since
        January 1, 1970)

    -   _string_ `nonce` — (Optional) Nonce to be used to create the HMAC

    -   _string_ `hash` — (Optional) Payload hash. Only used for payload
        validation.

    -   _string_ `payload` — (Optional) UTF-8-encoded request body (or
        "payload"). Only used for payload validation.

    -   _string_ `contentType` — (Optional) Payload content type. It is usually
        the value of the `Content-Type` header in the request. Only used for
        payload validation.

    -   _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
        milliseconds) of the client's local time compared to the server's local
        time

    -   _string_ `ext` — (Optional) Extra application-specific data

    -   _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/hueniverse/oz).

    -   _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/hueniverse/oz).

### `authenticate($responseHeaders, $credentials, $artifacts, $options)`

Validate the server's response.

#### `authenticate` (`Client` Class) Parameters

1.  _array_ `$responseHeaders` — (Required if `$options['required']` is `true`)
    HTTP headers from the server's response. May contain the following:

    -   `WWW-Authenticate` — (Required if `$options['required']` is `true`) Only
        set when the server's response is an HTTP `401 Unauthorized` response

    -   `Server-Authorization` — (Optional) Used to verify that the client is
        communicating with the correct server. Uses the same syntax as the
        `Authorization` header in the client's request.

    -   `Content-Type` — (Optional) Only used for payload validation.

1.  _array_ `$credentials` — (Required) Client's Hawk credentials, which include
    the following:

    -   _string_ `id` — (Required) Client's unique Hawk ID

    -   _string_ `key` — (Required) Secret key for the client

    -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
        an algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

1.  _array_ `$artifacts` — (Required) Components used to construct the request
    including the `Authorization` HTTP header. It includes the following:

    - _string_ `method` — Request method
    - _string_ `host` — Request host
    - _string_ `port` — Request port
    - _string_ `resource` — URL of the request relative to the host
    - _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
    - _string_ `nonce` — Nonce used to create the `mac`
    - _string_ `hash` — Payload hash. Only used for payload validation.
    - _string_ `ext` — Extra application-specific data
    - _string_ `app` — Application ID. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `dlg` — 'delegated-by' attribute. Only used with [Oz](https://github.com/hueniverse/oz).

1.  _array_ `$options` — (Optional) Includes the following:

    -   _string_ `payload` — (Optional) UTF-8-encoded request body (or
        "payload"). Only used for payload validation.

    -   _boolean_ `required` — (Optional, default: `false`) If server's response
        must contain the `Server-Authorization` HTTP header (must be included in
        `$requestHeaders`)

### `getBewit($uri, $method, $options)`

Generate a bewit value for the given URI.

Returns the bewit as a string.

#### `getBewit` Parameters

1.  _string_ or _array_ `$uri` — (Required) URI (as a string) for which to
    generate the bewit or an array that is the output of PHP's `parse_url()`

1.  _array_ `$options` — (Required) Items used to create the bewit. Includes the
    following:

    -   _array_ `credentials` — (Required) Client's Hawk credentials, which
        include the following:

        -   _string_ `id` — (Required) Client's unique Hawk ID

        -   _string_ `key` — (Required) Secret key for the client

        -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
            Must be an algorithm in the [`$algorithms` array property of the
            `Crypto` class](#algorithms-property).

    -   _integer_ `ttlSec` — (Required) Amount of time (in seconds) the bewit is
        valid

    -   _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
        milliseconds) of the client's local time compared to the server's local
        time

    -   _string_ `ext` — (Optional) Extra application-specific data

### `message($host, $port, $message, $options)`

Generate an authorization string for the given message.

Returns an array that contains the following:

- _string_ `id` — Client's unique Hawk ID
- _string_ `ts` — Timestamp (as milliseconds since January 1, 1970)
- _string_ `nonce` — Nonce used to create the `mac`
- _string_ `hash` — Payload hash. Only used for payload validation.
- _string_ `mac` — Authorization string for the message

#### `message` Parameters

1.  _string_ `$host` — (Required) Host portion of the URI the message will be
    sent to (e.g. example.com)

1.  _integer_ `$port` — (Required) Port number of the URI the message will be
    sent to

1.  _string_ `$message` — (Required) Message for which to generate an
    authorization

1.  _array_ `$options` — (Optional) Includes the following:

    -   _array_ `credentials` — (Required) Client's Hawk credentials, which
        include the following:

        -   _string_ `id` — (Required) Client's unique Hawk ID

        -   _string_ `key` — (Required) Secret key for the client

        -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC.
            Must be an algorithm in the [`$algorithms` array property of the
            `Crypto` class](#algorithms-property).

    -   _float_ `timestamp` — (Optional) Timestamp (as milliseconds since
        January 1, 1970)

    -   _string_ `nonce` — (Optional) Nonce to be used to create the HMAC of the
        message

    -   _float_ `localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
        milliseconds) of the client's local time compared to the server's local

`Client\ClientException` Class
------------------------------

The exception that is thrown when there is a _client_ Hawk error.

`Crypto\Crypto` Class
---------------------

Contains helper functions for various cryptographic operations.

### `$algorithms` Property

Supported HMAC algorithms. The algorithms supported by default are SHA-1
(`sha1`) and SHA-256 (`sha256`).

### `calculateMac($type, $credentials, $options)`

Calculate the HMAC digest using the given credentials.

Returns the HMAC digest as a string.

#### `calculateMac` Parameters

1.  _string_ `$type` — (Optional) Indicates the purpose of the MAC.'
    'Examples: `header`, `response`, `bewit`, `message`

1.  _array_ `$credentials` — (Required) Client's Hawk credentials, which include
    the following:

    -   _string_ `key` — (Required) Secret key for the client

    -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
        an algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

1.  _array_ `$options` — (Required) Components used to construct used to create
    the HMAC digest. It contains the following:

    - _string_ `method` — (Optional) Request method
    - _string_ `host` — (Optional) Request host
    - _string_ `port` — (Optional) Request port
    - _string_ `resource` — (Optional) URL of the request relative to the host
    - _string_ `ts` — (Optional) Timestamp (milliseconds since Jan. 1, 1970)
    - _string_ `nonce` — (Optional) Nonce used to create the `mac`
    - _string_ `hash` — (Optional) Payload hash. For payload validation only.
    - _string_ `ext` — (Optional) Extra application-specific data
    - _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/hueniverse/oz).

### `generateNormalizedString($type, $options)`

Create a normalized Hawk string that contains the given type and options.

Returns the normalized Hawk string.

#### `generateNormalizedString` Parameters

1.  _string_ `$type` — (Optional) Indicates the purpose of the MAC.
    Examples: `header`, `response`, `bewit`, `message`

1.  _array_ `$options` — (Required) Components used to construct used to create
    the HMAC digest. It contains the following:

    - _string_ `method` — (Optional) Request method
    - _string_ `host` — (Optional) Request host
    - _string_ `port` — (Optional) Request port
    - _string_ `resource` — (Optional) URL of the request relative to the host
    - _string_ `ts` — (Optional) Timestamp (milliseconds since Jan. 1, 1970)
    - _string_ `nonce` — (Optional) Nonce used to create the `mac`
    - _string_ `hash` — (Optional) Payload hash. For payload validation only.
    - _string_ `ext` — (Optional) Extra application-specific data
    - _string_ `app` — (Optional) Application ID. Only used with [Oz](https://github.com/hueniverse/oz).
    - _string_ `dlg` — (Optional) 'delegated-by' attribute. Only used with [Oz](https://github.com/hueniverse/oz).

### `calculatePayloadHash($payload, $algorithm, $contentType)`

Calculate the hash of the given payload and content type.

Returns the hash as a string.

#### `calculatePayloadHash` Parameters

1.  _string_ `$payload` — (Required) UTF-8-encoded request body (or "payload")

1.  _string_ `$algorithm` — (Required) Algorithm to be used for HMAC. Must be an
    algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

1.  _string_ `$contentType` — (Optional) Value of the `Content-Type` header in
    the request

### `calculateTsMac($ts, $credentials)`

Calculate the HMAC digest of the given timestamp using the given credentials.

Returns the HMAC digest as a string.

#### `calculateTsMac` Parameters

1.  _string_ `$ts` — (Required) Timestamp (as milliseconds since January 1,
    1970) for which to calculate the MAC

1.  _array_ `$credentials` — (Required) Client's Hawk credentials, which include
    the following:

    -   _string_ `key` — (Required) Secret key for the client

    -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
        an algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

### `timestampMessage($credentials, $localtimeOffsetMsec)`

Get the current time and calculate its HMAC using the given credentials.

Return an array that contains the following:

- _float_ `ts` — Current time (as seconds since January 1, 1970)
- _string_ `tsm` — HMAC of the current time (`ts`)

#### `timestampMessage` Parameters

1.  _array_ `$credentials` — (Required) Client's Hawk credentials, which include
    the following:

    -   _string_ `key` — (Required) Secret key for the client

    -   _string_ `algorithm` — (Required) Algorithm to be used for HMAC. Must be
        an algorithm in the [`$algorithms` array property of the `Crypto` class](#algorithms-property).

1.  _float_ `$localtimeOffsetMsec` — (Optional, default: `0`) Offset (in
    milliseconds) of the local time

`Utils\Utils` Class
-------------------

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

1.  _string_ `$header` — (Required) Value of the `Authorization` HTTP header

1.  _array_ `$keys` — (Optional, default: `id`, `ts`, `nonce`, `hash`, `ext`,
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
