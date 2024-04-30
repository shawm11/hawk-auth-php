<!-- omit in toc -->
# Hawk Authentication PHP

![Version Number](https://img.shields.io/packagist/v/shawm11/hawk-auth.svg)
![PHP Version](https://img.shields.io/packagist/php-v/shawm11/hawk-auth.svg)
[![License](https://img.shields.io/github/license/shawm11/hawk-auth-php.svg)](LICENSE.md)

A PHP implementation of the 9.0.2 version of the [**Hawk**](https://github.com/mozilla/hawk)
HTTP authentication scheme.

> [!IMPORTANT]
> Hawk is one of those rare projects that can be considered "complete".
> According to its [README](https://github.com/mozilla/hawk/blob/c1dd59bf0ca80210eedafcd30033e1858660a0e6/README.md),
> the protocol and documentation are considered complete. This means that
> changes to this repository be infrequent because only the development
> dependencies may need to be updated once every few years.
>
> If there is a bug or error in the documentation, please create an
> [issue](https://github.com/shawm11/hawk-auth-php/issues). The issue will
> receive a response or be resolved as soon as possible.

<!-- omit in toc -->
## Table of Contents

- [What is Hawk?](#what-is-hawk)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage Examples](#usage-examples)
- [API References](#api-references)
- [Security Considerations](#security-considerations)
- [Related Projects](#related-projects)
- [Contributing/Development](#contributingdevelopment)
- [Versioning](#versioning)
- [License](#license)

## What is Hawk?

According to the [Hawk's API documentation](https://github.com/mozilla/hawk/blob/c1dd59bf0ca80210eedafcd30033e1858660a0e6/API.md):

> **Hawk** is an HTTP authentication scheme providing mechanisms for making
> authenticated HTTP requests with partial cryptographic verification of the
> request and response, covering the HTTP method, request URI, host, and
> optionally the request payload.

Note that Hawk is not a complete replacement of OAuth. It is candidly stated in
the [_Frequently Asked Questions_ section of the Hawk API documentation](https://github.com/mozilla/hawk/blob/c1dd59bf0ca80210eedafcd30033e1858660a0e6/API.md#does-hawk-have-anything-to-do-with-oauth)
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
> third party. If you are looking for an OAuth alternative, check out [Oz](https://github.com/shawm11/oz-auth-php).

More more information about Hawk, check out its [API documentation](https://github.com/mozilla/hawk/blob/c1dd59bf0ca80210eedafcd30033e1858660a0e6/API.md)

## Getting Started

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

## Usage Examples

The examples in this section do not work without modification. However, these
examples should be enough to demonstrate how to use this package. Because PHP is
a language most commonly used for server logic, the "Server" usage is more
common than the "Client" usage.

- [Server Example](docs/usage-examples/ServerExample.php)
- [Client Example](docs/usage-examples/ClientExample.php)

## API References

- [Server API](docs/api-reference/server-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Server` namespace
- [Client API](docs/api-reference/server-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Client` namespace
- [Utils API](docs/api-reference/utils-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Utils` namespace
- [Crypto API](docs/api-reference/crypto-api.md) — API reference for the classes
  in the `Shawm11\Hawk\Crypto` namespace

## Security Considerations

See the [Security Considerations](https://github.com/mozilla/hawk/blob/c1dd59bf0ca80210eedafcd30033e1858660a0e6/API.md#security-considerations)
section of [Hawk's API documentation](https://github.com/mozilla/hawk/blob/c1dd59bf0ca80210eedafcd30033e1858660a0e6/API.md).

## Related Projects

- [Oz PHP Implementation](https://github.com/shawm11/oz-auth-php) — Oz is a web
  authorization protocol that is an alternative to OAuth 1.0a and OAuth 2.0
  three-legged authorization. Oz utilizes both Hawk and _iron_.
- [Iron PHP Implementation](https://github.com/shawm11/iron-crypto-php) — _iron_
  (spelled with all lowercase), a cryptographic utility for sealing a JSON
  object into an encapsulated token. _iron_ can be considered as an
  alternative to JSON Web Tokens (JWT).

## Contributing/Development

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on coding style, Git
commit message guidelines, and other development information.

## Versioning

This project uses [SemVer](http://semver.org/) for versioning. For the versions
available, see the tags on this repository.

## License

This project is open-sourced software licensed under the
[MIT license](https://opensource.org/licenses/MIT).
