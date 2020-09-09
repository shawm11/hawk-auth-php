Hawk Authentication PHP
=======================

![Version Number](https://img.shields.io/packagist/v/shawm11/hawk-auth.svg)
![PHP Version](https://img.shields.io/packagist/php-v/shawm11/hawk-auth.svg)
[![License](https://img.shields.io/github/license/shawm11/hawk-auth-php.svg)](LICENSE.md)

A PHP implementation of the 8.0.0 version of the [**Hawk**](https://github.com/outmoded/hawk)
HTTP authentication scheme.

**NOTICE**: Although the original JavaScript version of [Hawk](https://github.com/outmoded/hawk)
will not be maintained anymore, **this library will continue to be maintained**.
The original JavaScript version of Hawk was complete and only had periodic
documentation and library dependency updates.

Table of Contents
-----------------

<!--lint disable list-item-spacing-->

- [What is Hawk?](#what-is-hawk)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage Examples](#usage-examples)
  - [Server](#server)
  - [Client](#client)
- [API References](#api-references)
- [Security Considerations](#security-considerations)
- [Related Projects](#related-projects)
- [Contributing/Development](#contributingdevelopment)
- [Versioning](#versioning)
- [License](#license)

<!--lint enable list-item-spacing-->

What is Hawk?
-------------

According to the [Hawk README](https://github.com/outmoded/hawk/blob/84487d5a030c14707aa852b7800eee841d8029ae/README.md):

> **Hawk** is an HTTP authentication scheme using a message authentication code
> (MAC) algorithm to provide partial HTTP request cryptographic verification.

Note that Hawk is not a complete replacement of OAuth. It is candidly stated in
the [_Frequently Asked Questions_ section of the Hawk README] (https://github.com/outmoded/hawk/blob/84487d5a030c14707aa852b7800eee841d8029ae/README.md#does-hawk-have-anything-to-do-with-oauth)
that:

> **Hawk** was originally proposed as the OAuth MAC Token specification.
> However, the OAuth working group in its consistent incompetence failed to
> produce a final, usable solution to address one of the most popular use cases
> of OAuth 1.0 - using it to authenticate simple client-server transactions
> (i.e. two-legged). As you can guess, the OAuth working group is still hard at
> work to produce more garbage.
>
> **Hawk** provides a simple HTTP authentication scheme for making client-server
> requests. It does not address the OAuth use case of delegating access to a
> third party. If you are looking for an OAuth alternative, check out [Oz] (https://github.com/shawm11/oz-auth-php).

More more information about Hawk, check out its [README](https://github.com/outmoded/hawk/blob/84487d5a030c14707aa852b7800eee841d8029ae/README.md)

Getting Started
---------------

### Prerequisites

- Git 2.9+
- PHP 5.5.0+
- OpenSSL PHP Extension
- JSON PHP Extension
- [Composer](https://getcomposer.org/)

### Installation

Download and install using [Composer](https://getcomposer.org/):

```shell
composer require shawm11/hawk-auth
```

Usage Examples
--------------

The examples in this section do not work without modification. However, these
examples should be enough to demonstrate how to use this package.

### Server Example

Because PHP is a language most commonly used for server logic, the "Server"
usage is more common than the "Client" usage.

```php
<?php

use Shawm11\Hawk\Server\Server as HawkServer;
use Shawm11\Hawk\Server\ServerException as HawkServerException;
use Shawm11\Hawk\Server\BadRequestException as HawkBadRequestException;
use Shawm11\Hawk\Server\UnauthorizedException as HawkUnauthorizedException;

// A fictional function that handles an incoming request
function handleRequest() {
    $hawkServer = new HawkServer;
    $result = [];
	// Pretend to get request data from a client
	$requestData = [
		'method' => 'GET',
		'url' => '/resource/4?a=1&b=2',
		'host' => 'example.com',
		'port' => 8080,
        // Authorization header
		'authorization' => 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="'
	];
    // Function for retrieving credentials
    $credentialsFunc = function ($id) {
        // Pretend to retrieve the credentials (maybe from database) using the given ID ($id)
        $credentials = [
            'id' => '123456',
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => 'sha256',
            'user' => 'Steve'
        ];

        return $credentials;
    };

    try {
        $result = $hawkServer->authenticate($requestData, $credentialsFunc);
    } catch (HawkBadRequestException $e) {
        $httpStatusCode = $e->getCode();

        // Send HTTP status 400 (Bad Request) response...

        return;
    } catch (HawkUnauthorizedException $e) {
        $httpStatusCode = $e->getCode();
        // Run a fictional function that sets the header
    	setHeaderSomehow('WWW-Authenticate', $e->getWwwAuthenticateHeader());

        // Send HTTP status 401 (Unauthorized) response...

        return;
    } catch (HawkServerException $e) {
        echo 'ERROR: ' . $e->getMessage();
        return;
    }

    $credentials = $result['credentials']; // an array
    $artifacts = $result['artifacts']; // an array

    // Do some more stuff

    // Then send an authenticated response (See `sendResponse` function below)
    sendResponse($hawkServer, $credentials, $artifacts);
}

function sendResponse($hawkServer, $credentials, $artifacts) {
	$header = '';

    try {
        $header = $hawkServer->header($credentials, $artifact); // Output is a string
    } catch (HawkServerException $e) {
        echo 'ERROR: ' . $e->getMessage();
        return;
	}

	// Run a fictional function that sets the header
	setHeaderSomehow('Server-Authorization', $header);

	// Now do some other stuff to send the response
}
```

### Client Example

```php
<?php

use Shawm11\Hawk\Client\Client as HawkClient;
use Shawm11\Hawk\Client\ClientException as HawkClientException;

// A fictional function that makes an authenticated request to the server
function makeRequest($requestData) {
    $hawkClient = new HawkClient;
    $result = [];
	$uri = 'http://example.com/resource?a=b';
	$options = [
        // This is required
		'credentials' => [
			'id' => 'dh37fgj492je',
            'key' => 'aoijedoaijsdlaksjdl',
            'algorithm' => 'sha256'
		]
	];

    try {
        $result = $hawkClient->header($uri, 'POST', $options);
    } catch (HawkClientException $e) {
        echo 'ERROR: ' . $e->getMessage();
        return;
    }

    $header = $result['header']; // a string
    $artifacts = $result['artifacts']; // an array

	// Run a fictional function that sets the header
	setHeaderSomehow('Authorization', $header);

    // Do some more stuff before sending request

	// Now send the request
	sendRequestSomehow(); // Not a real function

	// Wait for response from server...

    // Now do some stuff after receiving response (See the `responseCallback` function below)
    responseCallback($hawkClient, $options['credentials'], $artifacts);
}

function responseCallback($hawkClient, $credentials, $artifacts) {
    // Somehow get the headers used in the response
	$responseHeaders = [
        // Only need these 3 headers
		'Server-Authorization' => 'some stuff',
		'WWW-Authentication' => 'some more stuff',
		'Content-Type' => 'application/json' // A different content type can be used
	];

    // Validate the server's response
    try {
        // If the server's response is valid, the parsed response headers are
        // returned as an array
        $parsedHeaders = $hawkClient->authenticate($responseHeaders, $credentials, $artifacts);
    } catch (HawkClientException $e) {
        // If the server's response is invalid, an error is thrown
        echo 'ERROR: ' . $e->getMessage();
        return;
	}

	// Now do some other stuff with the response
}
```

API References
--------------

<!--lint disable list-item-spacing-->

- [Server API](docs/api-reference/server-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Server` namespace
- [Client API](docs/api-reference/server-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Client` namespace
- [Utils API](docs/api-reference/utils-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Utils` namespace
- [Crypto API](docs/api-reference/crypto-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Crypto` namespace

<!--lint enable list-item-spacing-->

Security Considerations
-----------------------

See the [Security Considerations](https://github.com/outmoded/hawk/blob/84487d5a030c14707aa852b7800eee841d8029ae/README.md#security-considerations)
section of [Hawk's README](https://github.com/outmoded/hawk/blob/84487d5a030c14707aa852b7800eee841d8029ae/README.md).

Related Projects
----------------

-   [Oz PHP Implementation](https://github.com/shawm11/oz-auth-php) — Oz is a
    web authorization protocol that is an alternative to OAuth 1.0a and
    OAuth 2.0 three-legged authorization. Oz utilizes both Hawk and _iron_.

-   [Iron PHP Implementation](https://github.com/shawm11/iron-crypto-php) —
    _iron_ (spelled with all lowercase), a cryptographic utility for sealing a
    JSON object into an encapulated token. _iron_ can be considered as an
    alternative to JSON Web Tokens (JWT).

Contributing/Development
------------------------

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on coding style, Git
commit message guidelines, and other development information.

Versioning
----------

This project uses [SemVer](http://semver.org/) for versioning. For the versions
available, see the tags on this repository.

License
-------

This project is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
