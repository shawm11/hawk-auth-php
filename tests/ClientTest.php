<?php

namespace Shawm11\Hawk\Tests;

use PHPUnit\Framework\TestCase;
use Shawm11\Hawk\Crypto\Crypto;
use Shawm11\Hawk\Client\Client;
use Shawm11\Hawk\Client\ClientException;

class ClientTest extends TestCase
{
    use \Codeception\Specify;
    use \Codeception\AssertThrows;

    /**
     * @return void
     */
    public function testHeader()
    {
        $this->describe('Client::header()', function () {

            $this->it('should return a valid authorization header (SHA1)', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $header = (new Client)->header(
                    'http://example.net/somewhere/over/the/rainbow',
                    'POST',
                    [
                        'credentials' => $credentials,
                        'ext' => 'Bazinga!',
                        'timestamp' => 1353809207,
                        'nonce' => 'Ygvqdz',
                        'payload' => 'something to write about'
                    ]
                )['header'];

                expect($header)->toEqual(
                    'Hawk id="123456", ts="1353809207", nonce="Ygvqdz"'
                    . ', hash="bsvY3IfUllw6V5rvk4tStEvpBhE=", ext="Bazinga!"'
                    . ', mac="qbf1ZPG/r/e06F4ht+T77LXi5vw="'
                );
            });

            $this->it('should return a valid authorization header (SHA256)', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha256'
                ];

                $header = (new Client)->header(
                    'https://example.net/somewhere/over/the/rainbow',
                    'POST',
                    [
                        'credentials' => $credentials,
                        'ext' => 'Bazinga!',
                        'timestamp' => 1353809207,
                        'nonce' => 'Ygvqdz',
                        'payload' => 'something to write about',
                        'contentType' => 'text/plain'
                    ]
                )['header'];

                expect($header)->toEqual(
                    'Hawk id="123456", ts="1353809207", nonce="Ygvqdz"'
                    . ', hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="'
                    . ', ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="'
                );
            });

            $this->it('should return a valid authorization header (no ext)', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha256'
                ];

                $header = (new Client)->header(
                    'https://example.net/somewhere/over/the/rainbow',
                    'POST',
                    [
                        'credentials' => $credentials,
                        'timestamp' => 1353809207,
                        'nonce' => 'Ygvqdz',
                        'payload' => 'something to write about',
                        'contentType' => 'text/plain'
                    ]
                )['header'];

                expect($header)->toEqual(
                    'Hawk id="123456", ts="1353809207", nonce="Ygvqdz"'
                    . ', hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="'
                    . ', mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="'
                );
            });

            $this->it('should return a valid authorization header (null ext)', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha256'
                ];

                $header = (new Client)->header(
                    'https://example.net/somewhere/over/the/rainbow',
                    'POST',
                    [
                        'credentials' => $credentials,
                        'ext' => null,
                        'timestamp' => 1353809207,
                        'nonce' => 'Ygvqdz',
                        'payload' => 'something to write about',
                        'contentType' => 'text/plain'
                    ]
                )['header'];

                expect($header)->toEqual(
                    'Hawk id="123456", ts="1353809207", nonce="Ygvqdz"'
                    . ', hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="'
                    . ', mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="'
                );
            });

            $this->it('should return a valid authorization header (empty payload)', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha256'
                ];

                $header = (new Client)->header(
                    'https://example.net/somewhere/over/the/rainbow',
                    'POST',
                    [
                        'credentials' => $credentials,
                        'timestamp' => 1353809207,
                        'nonce' => 'Ygvqdz',
                        'payload' => '',
                        'contentType' => 'text/plain'
                    ]
                )['header'];

                expect($header)->toEqual(
                    'Hawk id="123456", ts="1353809207", nonce="Ygvqdz"'
                    . ', hash="q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA="'
                    . ', mac="U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM="'
                );
            });

            $this->it('should return a valid authorization header (pre hashed payload)', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha256'
                ];

                $options = [
                    'credentials' => $credentials,
                    'timestamp' => 1353809207,
                    'nonce' => 'Ygvqdz',
                    'payload' => 'something to write about',
                    'contentType' => 'text/plain'
                ];
                $options['hash'] = (new Crypto)->calculatePayloadHash(
                    $options['payload'],
                    $credentials['algorithm'],
                    $options['contentType']
                );

                $header = (new Client)->header(
                    'https://example.net/somewhere/over/the/rainbow',
                    'POST',
                    $options
                )['header'];

                expect($header)->toEqual(
                    'Hawk id="123456", ts="1353809207", nonce="Ygvqdz"'
                    . ', hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY="'
                    . ', mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="'
                );
            });

            $this->it('should throw an error if the URI is missing', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid argument type', function () {
                    (new Client)->header('', 'POST', ['foo' => 'bar']);
                });
            });

            $this->it('should throw an error if the URI is invalid', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid argument type', function () {
                    (new Client)->header(4, 'POST', ['foo' => 'bar']);
                });
            });

            $this->it('should throw an error if the method is missing', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid argument type', function () {
                    (new Client)->header('https://example.net/somewhere/over/the/rainbow', '', ['foo' => 'bar']);
                });
            });

            $this->it('should throw an error if the method is invalid', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid argument type', function () {
                    (new Client)->header('https://example.net/somewhere/over/the/rainbow', 5, []);
                });
            });

            $this->it('should throw an error if missing options are missing', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid argument type', function () {
                    (new Client)->header('https://example.net/somewhere/over/the/rainbow', 5, []);
                });
            });

            $this->it('should throw an error if the credentials ID is missing', function () {
                $credentials = [
                    // No `id`
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid credentials',
                    function () use ($credentials) {
                        (new Client)->header('https://example.net/somewhere/over/the/rainbow', 'POST', [
                            'credentials' => $credentials,
                            'ext' => 'Bazinga!',
                            'timestamp' => 1353809207,
                        ]);
                    }
                );
            });

            $this->it('should throw an error if the credentials are missing', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid credentials', function () {
                    (new Client)->header('https://example.net/somewhere/over/the/rainbow', 'POST', [
                        // No `credentials`
                        'ext' => 'Bazinga!',
                        'timestamp' => 1353809207,
                    ]);
                });
            });

            $this->it('should throw an error if the credentials are invalid', function () {
                $credentials = [
                    'id' => '123456',
                    // No `key`
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid credentials',
                    function () use ($credentials) {
                        (new Client)->header('https://example.net/somewhere/over/the/rainbow', 'POST', [
                            'credentials' => $credentials,
                            'ext' => 'Bazinga!',
                            'timestamp' => 1353809207,
                        ]);
                    }
                );
            });

            $this->it('should throw an error if the algorithm is invalid', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'hmac-sha-0'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Unknown algorithm',
                    function () use ($credentials) {
                        (new Client)->header('https://example.net/somewhere/over/the/rainbow', 'POST', [
                            'credentials' => $credentials,
                            'payload' => 'something, anything!',
                            'ext' => 'Bazinga!',
                            'timestamp' => 1353809207,
                        ]);
                    }
                );
            });
        });
    }

    /**
     * @return void
     */
    public function testAuthenticate()
    {
        $this->describe('Client::authenticate()', function () {

            $this->it('should throw an error if the header is invalid', function () {
                $responseHeaders = [
                    'Server-Authorization' => 'Hawk mac="abc", bad="xyz"'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid Server-Authorization header',
                    function () use ($responseHeaders) {
                        (new Client)->authenticate($responseHeaders, [], []);
                    }
                );
            });

            $this->it('should throw an error if the MAC is invalid', function () {
                $responseHeaders = [
                    'content-type' => 'text/plain',
                    'server-authorization' => 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE="'
                                            . ', hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="'
                                            . ', ext="response-specific"'
                ];

                $artifacts = [
                    'method' => 'POST',
                    'host' => 'example.com',
                    'port' => '8080',
                    'resource' => '/resource/4?filter=a',
                    'ts' => '1362336900',
                    'nonce' => 'eb5S_L',
                    'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    'ext' => 'some-app-data',
                    'app' => null,
                    'dlg' => null,
                    'mac' => 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
                    'id' => '123456',
                ];

                $credentials = [
                    'id' => '123456',
                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    'algorithm' => 'sha256',
                    'user' => 'steve'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Bad response MAC',
                    function () use ($responseHeaders, $credentials, $artifacts) {
                        (new Client)->authenticate($responseHeaders, $credentials, $artifacts);
                    }
                );
            });

            $this->it('should return headers if it ignores the hash', function () {
                $responseHeaders = [
                    'content-type' => 'text/plain',
                    'server-authorization' => 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE="'
                                            . ', hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="'
                                            . ', ext="response-specific"'
                ];

                $artifacts = [
                    'method' => 'POST',
                    'host' => 'example.com',
                    'port' => '8080',
                    'resource' => '/resource/4?filter=a',
                    'ts' => '1362336900',
                    'nonce' => 'eb5S_L',
                    'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    'ext' => 'some-app-data',
                    'app' => null,
                    'dlg' => null,
                    'mac' => 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
                    'id' => '123456',
                ];

                $credentials = [
                    'id' => '123456',
                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    'algorithm' => 'sha256',
                    'user' => 'steve'
                ];

                $headers = (new Client)->authenticate($responseHeaders, $credentials, $artifacts);

                expect($headers)->toEqual([
                    'server-authorization' => [
                        'mac' => 'XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=',
                        'hash' => 'f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=',
                        'ext' => 'response-specific'
                    ]
                ]);
            });

            $this->it('should validate the response payload', function () {
                $payload = 'some reply';

                $responseHeaders = [
                    'content-type' => 'text/plain',
                    'server-authorization' => 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8="'
                                            . ', hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="'
                                            . ', ext="response-specific"'
                ];

                $credentials = [
                    'id' => '123456',
                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    'algorithm' => 'sha256',
                    'user' => 'steve'
                ];

                $artifacts = [
                    'method' => 'POST',
                    'host' => 'example.com',
                    'port' => '8080',
                    'resource' => '/resource/4?filter=a',
                    'ts' => '1453070933',
                    'nonce' => '3hOHpR',
                    'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    'ext' => 'some-app-data',
                    'app' => null,
                    'dlg' => null,
                    'mac' => '/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs=',
                    'id' => '123456',
                ];

                $headers = (new Client)->authenticate(
                    $responseHeaders,
                    $credentials,
                    $artifacts,
                    ['payload' => $payload]
                );

                expect($headers)->toEqual([
                    'server-authorization' => [
                        'mac' => 'odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=',
                        'hash' => 'f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=',
                        'ext' => 'response-specific'
                    ]
                ]);
            });

            $this->it('should throw an error if the response payload is invalid', function () {
                $payload = 'wrong reply';

                $responseHeaders = [
                    'content-type' => 'text/plain',
                    'server-authorization' => 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8="'
                                            . ', hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="'
                                            . ', ext="response-specific"'
                ];

                $credentials = [
                    'id' => '123456',
                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    'algorithm' => 'sha256',
                    'user' => 'steve'
                ];

                $artifacts = [
                    'method' => 'POST',
                    'host' => 'example.com',
                    'port' => '8080',
                    'resource' => '/resource/4?filter=a',
                    'ts' => '1453070933',
                    'nonce' => '3hOHpR',
                    'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    'ext' => 'some-app-data',
                    'app' => null,
                    'dlg' => null,
                    'mac' => '/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs=',
                    'id' => '123456',
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Bad response payload MAC',
                    function () use ($responseHeaders, $credentials, $artifacts, $payload) {
                        (new Client)->authenticate(
                            $responseHeaders,
                            $credentials,
                            $artifacts,
                            ['payload' => $payload]
                        );
                    }
                );
            });

            $this->it('should throw an error if the WWW-Authenticate header format is invalid', function () {
                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid WWW-Authenticate header',
                    function () {
                        (new Client)->authenticate(
                            [
                                'www-authenticate' => 'Hawk ts="1362346425875"'
                                                    . ', tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo="'
                                                    . ', x="Stale timestamp"'
                            ],
                            [],
                            []
                        );
                    }
                );
            });

            $this->it(
                'should throw an error if the WWW-Authenticate header format is invalid (timestamp)',
                function () {
                    $this->assertThrowsWithMessage(
                        ClientException::class,
                        'Invalid server timestamp hash',
                        function () {
                            (new Client)->authenticate(
                                [
                                    'www-authenticate' => 'Hawk ts="1362346425875"'
                                                        . ', tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo="'
                                                        . ', error="Stale timestamp"'
                                ],
                                [
                                    'id' => '123456',
                                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                                    'algorithm' => 'sha256',
                                    'user' => 'steve'
                                ],
                                []
                            );
                        }
                    );
                }
            );

            $this->it('should skip `tsm` validation when missing `ts`', function () {
                $headers = (new Client)->authenticate(
                    [
                        'www-authenticate' => 'Hawk error="Stale timestamp"'
                    ],
                    [],
                    []
                );

                expect($headers)->toEqual(['www-authenticate' => ['error' => 'Stale timestamp']]);
            });
        });
    }

    /**
     * @return void
     */
    public function testGetBewit()
    {
        $this->describe('Client::getBewit()', function () {

            $this->it('should return a string', function () {
                $bewit = (new Client)->getBewit(
                    'http://example.net/somewhere/over/the/rainbow',
                    [
                        'ttlSec' => 60,
                        'credentials' => [
                            'id' => '123456',
                            'key' => '2983d45yun89q',
                            'algorithm' => 'sha1'
                        ]
                    ]
                );

                expect(gettype($bewit))->toEqual('string');
            });

            $this->it('throws an error if the URI is not a string or an array', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid inputs', function () {
                    (new Client)->getBewit(
                        5,
                        [
                            'ttlSec' => 60,
                            'credentials' => [
                                'id' => '123456',
                                'key' => '2983d45yun89q',
                                'algorithm' => 'sha1'
                            ]
                        ]
                    );
                });
            });

            $this->it('throws an error if the URI is null', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid inputs', function () {
                    (new Client)->getBewit(
                        null,
                        [
                            'ttlSec' => 60,
                            'credentials' => [
                                'id' => '123456',
                                'key' => '2983d45yun89q',
                                'algorithm' => 'sha1'
                            ]
                        ]
                    );
                });
            });

            $this->it('throws an error if the options are not an array', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid inputs', function () {
                    (new Client)->getBewit('http://example.net/somewhere/over/the/rainbow', '');
                });
            });

            $this->it('throws an error if the options is null', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid inputs', function () {
                    (new Client)->getBewit('http://example.net/somewhere/over/the/rainbow', null);
                });
            });

            $this->it('throws an error if the `ttlSec` in the options is missing', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid inputs', function () {
                    (new Client)->getBewit(
                        'http://example.net/somewhere/over/the/rainbow',
                        [
                            'credentials' => [
                                'id' => '123456',
                                'key' => '2983d45yun89q',
                                'algorithm' => 'sha1'
                            ]
                        ]
                    );
                });
            });

            $this->it('should throw an error if the credentials ID is invalid', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid credentials', function () {
                    (new Client)->getBewit(
                        'http://example.net/somewhere/over/the/rainbow',
                        [
                            'ttlSec' => 60,
                            'credentials' => [
                                'key' => '2983d45yun89q',
                                'algorithm' => 'sha1'
                            ]
                        ]
                    );
                });
            });

            $this->it('should throw an error if the credentials key is invalid', function () {
                $this->assertThrowsWithMessage(ClientException::class, 'Invalid credentials', function () {
                    (new Client)->getBewit(
                        'http://example.net/somewhere/over/the/rainbow',
                        [
                            'ttlSec' => 60,
                            'credentials' => [
                                'id' => '123456',
                                'algorithm' => 'sha1'
                            ]
                        ]
                    );
                });
            });
        });
    }

    /**
     * @return void
     */
    public function testMessage()
    {
        $this->describe('Client::message()', function () {

            $this->it('should generate authorization', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];
                $auth = (new Client)->message(
                    'example.com',
                    80,
                    'I am the boodyman',
                    [
                        'credentials' => $credentials,
                        'timestamp' => 1353809207,
                        'nonce' => 'abc123'
                    ]
                );

                expect($auth['ts'])->toEqual(1353809207);
                expect($auth['nonce'])->toEqual('abc123');
            });

            $this->it('should throw an error if the host is invalid', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid inputs',
                    function () use ($credentials) {
                        (new Client)->message(
                            5,
                            80,
                            'I am the boodyman',
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });

            $this->it('should throw an error if the port is invalid', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid inputs',
                    function () use ($credentials) {
                        (new Client)->message(
                            'example.com',
                            '80',
                            'I am the boodyman',
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });

            $this->it('should throw an error if the host is missing', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid inputs',
                    function () use ($credentials) {
                        (new Client)->message(
                            null,
                            80,
                            'I am the boodyman',
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });

            $this->it('should throw an error if the port is missing', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid inputs',
                    function () use ($credentials) {
                        (new Client)->message(
                            'example.com',
                            null,
                            'I am the boodyman',
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });

            $this->it('should throw an error if the message is null', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid inputs',
                    function () use ($credentials) {
                        (new Client)->message(
                            'example.com',
                            80,
                            null,
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });

            $this->it('should throw an error if the message is invalid', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid inputs',
                    function () use ($credentials) {
                        (new Client)->message(
                            'example.com',
                            80,
                            5,
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });

            $this->it('should throw an error if the options are missing', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid inputs',
                    function () {
                        (new Client)->message('example.com', 80, 'I am the boodyman', null);
                    }
                );
            });

            $this->it('should throw an error if the credentials ID is invalid', function () {
                $credentials = [
                    'key' => '2983d45yun89q',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid credentials',
                    function () use ($credentials) {
                        (new Client)->message(
                            'example.com',
                            80,
                            'I am the boodyman',
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });

            $this->it('should throw an error if the credentials key is invalid', function () {
                $credentials = [
                    'id' => '123456',
                    'algorithm' => 'sha1'
                ];

                $this->assertThrowsWithMessage(
                    ClientException::class,
                    'Invalid credentials',
                    function () use ($credentials) {
                        (new Client)->message(
                            'example.com',
                            80,
                            'I am the boodyman',
                            [
                                'credentials' => $credentials,
                                'timestamp' => 1353809207,
                                'nonce' => 'abc123'
                            ]
                        );
                    }
                );
            });
        });
    }
}
