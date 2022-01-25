<?php

namespace Shawm11\Hawk\Tests;

use PHPUnit\Framework\TestCase;
use Shawm11\Hawk\Utils\Utils;
use Shawm11\Hawk\Crypto\Crypto;
use Shawm11\Hawk\Client\Client;
use Shawm11\Hawk\Server\Server;
use Shawm11\Hawk\Server\ServerException;
use Shawm11\Hawk\Server\BadRequestException;
use Shawm11\Hawk\Server\UnauthorizedException;

class ServerTest extends TestCase
{
    use \Codeception\Specify;
    use \Codeception\AssertThrows;

    /**
     * @return void
     */
    public function testAuthenticate()
    {
        $this->describe('Server::authenticate()', function () {

            $this->it('should parse a valid authentication header (SHA1)', function () {
                $credentials = (new Server)->authenticate(
                    [
                        'method' => 'GET',
                        'url' => '/resource/4?filter=a',
                        'host' => 'example.com',
                        'port' => 8080,
                        'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2"'
                                         . ', mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
                    ],
                    function ($id) {
                        return $this->credentialsFunc($id);
                    },
                    [
                        'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                    ]
                )['credentials'];

                expect($credentials['user'])->toEqual('steve');
            });

            $this->it('should parse a valid authentication header (SHA256)', function () {
                    $credentials = (new Server)->authenticate(
                        [
                            'method' => 'GET',
                            'url' => '/resource/1?b=1&a=2',
                            'host' => 'example.com',
                            'port' => 8000,
                            'authorization' => 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2"'
                                             . ', mac="m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU="'
                                             . ', ext="some-app-data"'
                        ],
                        function ($id) {
                            return $this->credentialsFunc($id);
                        },
                        [
                            'localtimeOffsetMsec' => 1353832234000 - (new Utils)->now()
                        ]
                    )['credentials'];

                    expect($credentials['user'])->toEqual('steve');
            });

            $this->it('should parse a valid authentication header (host override)', function () {
                $credentials = (new Server)->authenticate(
                    [
                        'method' => 'GET',
                        'url' => '/resource/4?filter=a',
                        'host' => 'example1.com',
                        'port' => 8080,
                        'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2"'
                                         . ', mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
                    ],
                    function ($id) {
                        return $this->credentialsFunc($id);
                    },
                    [
                        'host' => 'example.com',
                        'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                    ]
                )['credentials'];

                expect($credentials['user'])->toEqual('steve');
            });

            $this->it('should parse a valid authentication header (host port override)', function () {
                $credentials = (new Server)->authenticate(
                    [
                        'method' => 'GET',
                        'url' => '/resource/4?filter=a',
                        'host' => 'example1.com',
                        'port' => 80,
                        'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2"'
                                         . ', mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
                    ],
                    function ($id) {
                        return $this->credentialsFunc($id);
                    },
                    [
                        'host' => 'example.com',
                        'port' => 8080,
                        'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                    ]
                )['credentials'];

                expect($credentials['user'])->toEqual('steve');
            });

            $this->it('should parse a valid authentication header (POST with payload)', function () {
                $credentials = (new Server)->authenticate(
                    [
                        'method' => 'POST',
                        'url' => '/resource/4?filter=a',
                        'host' => 'example.com',
                        'port' => 8080,
                        'authorization' => 'Hawk id="123456", ts="1357926341", nonce="1AwuJD"'
                                         . ', hash="1kFuupNATsh9T4rfyh1itrLl9hRTWlkXV97J7IJ4QKk="'
                                         . ', ext="some-app-data", mac="Y9wtRQxYhRa8q4oh9h/W4mfxkrZU2jFpyR7gEKN1uL0="'
                    ],
                    function ($id) {
                        return $this->credentialsFunc($id);
                    },
                    [
                        'payload' => 'body',
                        'localtimeOffsetMsec' => 1357926341000 - (new Utils)->now()
                    ]
                )['credentials'];

                expect($credentials['user'])->toEqual('steve');
            });

            $this->it('should error on missing hash', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Missing required payload hash',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/1?b=1&a=2',
                                'host' => 'example.com',
                                'port' => 8000,
                                'authorization' => 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2"'
                                                 . ', mac="m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU="'
                                                 . ', ext="some-app-data"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'payload' => 'body',
                                'localtimeOffsetMsec' => 1353832234000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on a stale timestamp', function () {
                try {
                    (new Server)->authenticate(
                        [
                            'method' => 'GET',
                            'url' => '/resource/4?filter=a',
                            'host' => 'example.com',
                            'port' => 8080,
                            'authorization' => 'Hawk id="123456", ts="1362337299", nonce="UzmxSs"'
                                             . ', ext="some-app-data"'
                                             . ', mac="wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w="'
                        ],
                        function ($id) {
                            return $this->credentialsFunc($id);
                        }
                    );
                } catch (UnauthorizedException $e) {
                    expect($e->getMessage())->toEqual('Stale timestamp');

                    $header = $e->getWwwAuthenticateHeader();
                    $matches = [];
                    preg_match(
                        '/^Hawk ts\=\"(\d+)\"\, tsm\=\"([^\"]+)\"\, error=\"Stale timestamp\"$/',
                        $header,
                        $matches
                    );
                    $ts = $matches[1];
                    $now = (new Utils)->now();

                    expect(abs((intval($ts, 10) * 1000) - $now))->toBeLessThanOrEqualTo(1000);

                    $credentials = $this->credentialsFunc('123456');
                    $attributes = [
                        'method' => 'GET',
                        'host' => 'example.com',
                        'port' => 8080,
                        'resource' => '/resource/4?filter=a',
                        'ts' => $ts,
                        'nonce' => 'UzmxSs',
                        'ext' => 'some-app-data',
                        'mac' => 'wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=',
                        'id' => '123456'
                    ];

                    // Should not throw error
                    (new Client)->authenticate(['www-authenticate' => $header], $credentials, $attributes);

                    return;
                }

                $this->fail('The expected exception was not thrown.');
            });

            $this->it('should error on a replay', function () {
                $req = [
                    'method' => 'GET',
                    'url' => '/resource/4?filter=a',
                    'host' => 'example.com',
                    'port' => 8080,
                    'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                     . ', mac="bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw="'
                                     . ', ext="hello"'
                ];

                $memoryCache = [];
                $options = [
                    'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now(),
                    'nonceFunc' => function ($key, $nonce, $ts) use (&$memoryCache) {
                        $i = $key . $nonce;

                        if (!empty($memoryCache[$i])) {
                            throw new \Exception();
                        }

                        $memoryCache[$i] = true;
                    }
                ];

                $credentials = (new Server)->authenticate(
                    $req,
                    function ($id) {
                        return $this->credentialsFunc($id);
                    },
                    $options
                )['credentials'];

                expect($credentials['user'])->toEqual('steve');

                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Invalid nonce',
                    function () use ($req, $options) {
                        (new Server)->authenticate(
                            $req,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            $options
                        );
                    }
                );
            });

            $this->it('should not error on nonce collision if keys differ', function () {
                $reqSteve = [
                    'method' => 'GET',
                    'url' => '/resource/4?filter=a',
                    'host' => 'example.com',
                    'port' => 8080,
                    'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", mac="bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=", ext="hello"'
                ];

                $reqBob = [
                    'method' => 'GET',
                    'url' => '/resource/4?filter=a',
                    'host' => 'example.com',
                    'port' => 8080,
                    'authorization' => 'Hawk id="456", ts="1353788437", nonce="k3j4h2", mac="LXfmTnRzrLd9TD7yfH+4se46Bx6AHyhpM94hLCiNia4=", ext="hello"'
                ];

                $credentialsFunction = function ($id) {
                    $credentials = [
                        '123' => [
                            'id',
                            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                            'algorithm' => ($id === '1' ? 'sha1' : 'sha256'),
                            'user' => 'steve'
                        ],
                        '456' => [
                            'id',
                            'key' => 'xrunpaw3489ruxnpa98w4rxnwerxhqb98rpaxn39848',
                            'algorithm' => ($id === '1' ? 'sha1' : 'sha256'),
                            'user' => 'bob'
                        ]
                    ];

                    return $credentials[$id];
                };

                $memoryCache = [];
                $options = [
                    'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now(),
                    'nonceFunc' => function ($key, $nonce, $ts) use (&$memoryCache) {
                        $i = $key . $nonce;

                        if (!empty($memoryCache[$i])) {
                            throw new \Exception();
                        }

                        $memoryCache[$i] = true;
                    }
                ];

                $credentials1 = (new Server)->authenticate($reqSteve, $credentialsFunction, $options)['credentials'];
                $credentials2 = (new Server)->authenticate($reqBob, $credentialsFunction, $options)['credentials'];

                expect($credentials1['user'])->toEqual('steve');
                expect($credentials2['user'])->toEqual('bob');
            });

            $this->it('should error on an invalid authentication header: wrong scheme', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    '',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Basic asdasdasdasd'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an invalid authentication header: no scheme', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid header syntax',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => '!@#'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an missing authorization header', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    '',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an missing host', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid Host header',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an missing port', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid Host header',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an missing authorization attribute (id)', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Missing attributes',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an missing authorization attribute (ts)', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Missing attributes',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an missing authorization attribute (nonce)', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Missing attributes',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an missing authorization attribute (mac)', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Missing attributes',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an unknown authorization attribute', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Unknown attribute: x',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2", x="3"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an bad authorization header format', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Bad header format',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123\\", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an bad authorization attribute value', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Bad attribute value: id',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => "Hawk id=\"\t\", ts=\"1353788437\", nonce=\"k3j4h2\""
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an empty authorization attribute value', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Bad attribute value: id',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on duplicated authorization attribute key', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Duplicate attribute: id',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", id="456", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on an invalid authorization header format', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid header syntax',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on credentialsFunc error', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Unknown user',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                throw new \Exception('Unknown user');
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on missing credentials', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Unknown credentials',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return null;
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on invalid credentials (id)', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Invalid credentials',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return [
                                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                                    'user' => 'steve'
                                ];
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on invalid credentials (key)', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Invalid credentials',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return [
                                    'id' => '23434d3q4d5345d',
                                    'user' => 'steve'
                                ];
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on unknown credentials algorithm', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Unknown algorithm',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return [
                                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                                    'algorithm' => 'hmac-sha-0',
                                    'user' => 'steve'
                                ];
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });

            $this->it('should error on unknown bad MAC', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Bad MAC',
                    function () {
                        (new Server)->authenticate(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="123", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos="'
                                                 . ', ext="hello"'
                            ],
                            function ($id) {
                                return [
                                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                                    'algorithm' => 'sha256',
                                    'user' => 'steve'
                                ];
                            },
                            [
                                'localtimeOffsetMsec' => 1353788437000 - (new Utils)->now()
                            ]
                        );
                    }
                );
            });
        });
    }

    /**
     * @return void
     */
    public function testHeader()
    {
        $this->describe('Server::header()', function () {

            $this->it('should generate header', function () {
                $header = (new Server)->header(
                    [
                        'id' => '123456',
                        'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        'algorithm' => 'sha256',
                        'user' => 'steve'
                    ],
                    [
                        'method' => 'POST',
                        'host' => 'example.com',
                        'port' => '8080',
                        'resource' => '/resource/4?filter=a',
                        'ts' => '1398546787',
                        'nonce' => 'xUwusx',
                        'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                        'ext' => 'some-app-data',
                        'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                        'id' => '123456'
                    ],
                    [
                        'payload' => 'some reply',
                        'contentType' => 'text/plain',
                        'ext' => 'response-specific'
                    ]
                );

                expect($header)->toEqual(
                    'Hawk mac="n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE="'
                    . ', hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="'
                    . ', ext="response-specific"'
                );
            });

            $this->it('should generate header (empty payload)', function () {
                $header = (new Server)->header(
                    [
                        'id' => '123456',
                        'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        'algorithm' => 'sha256',
                        'user' => 'steve'
                    ],
                    [
                        'method' => 'POST',
                        'host' => 'example.com',
                        'port' => '8080',
                        'resource' => '/resource/4?filter=a',
                        'ts' => '1398546787',
                        'nonce' => 'xUwusx',
                        'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                        'ext' => 'some-app-data',
                        'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                        'id' => '123456'
                    ],
                    [
                        'payload' => '',
                        'contentType' => 'text/plain',
                        'ext' => 'response-specific'
                    ]
                );

                expect($header)->toEqual(
                    'Hawk mac="i8/kUBDx0QF+PpCtW860kkV/fa9dbwEoe/FpGUXowf0="'
                    . ', hash="q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA="'
                    . ', ext="response-specific"'
                );
            });

            $this->it('should generate header (missing payload)', function () {
                $header = (new Server)->header(
                    [
                        'id' => '123456',
                        'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        'algorithm' => 'sha256',
                        'user' => 'steve'
                    ],
                    [
                        'method' => 'POST',
                        'host' => 'example.com',
                        'port' => '8080',
                        'resource' => '/resource/4?filter=a',
                        'ts' => '1398546787',
                        'nonce' => 'xUwusx',
                        'ext' => 'some-app-data',
                        'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                        'id' => '123456'
                    ],
                    [
                        'contentType' => 'text/plain',
                        'ext' => 'response-specific'
                    ]
                );

                expect($header)->toEqual(
                    'Hawk mac="h+gDSdLlERbcJ3YcJfdOfTuJfRB/yePqbaWOHthpUyc="'
                    . ', ext="response-specific"'
                );
            });

            $this->it('should generate header (null payload)', function () {
                $header = (new Server)->header(
                    [
                        'id' => '123456',
                        'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        'algorithm' => 'sha256',
                        'user' => 'steve'
                    ],
                    [
                        'method' => 'POST',
                        'host' => 'example.com',
                        'port' => '8080',
                        'resource' => '/resource/4?filter=a',
                        'ts' => '1398546787',
                        'nonce' => 'xUwusx',
                        'ext' => 'some-app-data',
                        'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                        'id' => '123456'
                    ],
                    [
						'payload' => null,
                        'contentType' => 'text/plain',
                        'ext' => 'response-specific'
                    ]
                );

                expect($header)->toEqual(
                    'Hawk mac="h+gDSdLlERbcJ3YcJfdOfTuJfRB/yePqbaWOHthpUyc="'
                    . ', ext="response-specific"'
                );
            });

            $this->it('should generate header (pre calculated hash)', function () {
                $credentials = [
                    'id' => '123456',
                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    'algorithm' => 'sha256',
                    'user' => 'steve'
                ];
                $options = [
                    'payload' => 'some reply',
                    'contentType' => 'text/plain',
                    'ext' => 'response-specific'
                ];
                $options['hash'] = (new Crypto)->calculatePayloadHash(
                    $options['payload'],
                    $credentials['algorithm'],
                    $options['contentType']
                );

                $header = (new Server)->header(
                    $credentials,
                    [
                        'method' => 'POST',
                        'host' => 'example.com',
                        'port' => '8080',
                        'resource' => '/resource/4?filter=a',
                        'ts' => '1398546787',
                        'nonce' => 'xUwusx',
                        'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                        'ext' => 'some-app-data',
                        'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                        'id' => '123456'
                    ],
                    $options
                );

                expect($header)->toEqual(
                    'Hawk mac="n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE="'
                    . ', hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="'
                    . ', ext="response-specific"'
                );
            });

            $this->it('should generate header (null ext)', function () {
                $header = (new Server)->header(
                    [
                        'id' => '123456',
                        'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        'algorithm' => 'sha256',
                        'user' => 'steve'
                    ],
                    [
                        'method' => 'POST',
                        'host' => 'example.com',
                        'port' => '8080',
                        'resource' => '/resource/4?filter=a',
                        'ts' => '1398546787',
                        'nonce' => 'xUwusx',
                        'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                        'ext' => 'some-app-data',
                        'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                        'id' => '123456'
                    ],
                    [
                        'payload' => 'some reply',
                        'contentType' => 'text/plain',
                        'ext' => null
                    ]
                );

                expect($header)->toEqual(
                    'Hawk mac="6PrybJTJs20jsgBw5eilXpcytD8kUbaIKNYXL+6g0ns="'
                    . ', hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM="'
                );
            });

            $this->it('should error on missing artifacts', function () {
                $this->assertThrowsWithMessage(ServerException::class, 'Invalid inputs', function () {
                    (new Server)->header(
                        [
                            'id' => '123456',
                            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                            'algorithm' => 'sha256',
                            'user' => 'steve'
                        ],
                        null,
                        [
                            'payload' => 'some reply',
                            'contentType' => 'text/plain',
                            'ext' => 'response-specific'
                        ]
                    );
                });
            });

            $this->it('should error on invalid artifacts', function () {
                $this->assertThrowsWithMessage(ServerException::class, 'Invalid inputs', function () {
                    (new Server)->header(
                        [
                            'id' => '123456',
                            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                            'algorithm' => 'sha256',
                            'user' => 'steve'
                        ],
                        5,
                        [
                            'payload' => 'some reply',
                            'contentType' => 'text/plain',
                            'ext' => 'response-specific'
                        ]
                    );
                });
            });

            $this->it('should error on missing credentials', function () {
                $this->assertThrowsWithMessage(ServerException::class, 'Invalid credentials', function () {
                    (new Server)->header(
                        null,
                        [
                            'method' => 'POST',
                            'host' => 'example.com',
                            'port' => '8080',
                            'resource' => '/resource/4?filter=a',
                            'ts' => '1398546787',
                            'nonce' => 'xUwusx',
                            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                            'ext' => 'some-app-data',
                            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                            'id' => '123456'
                        ],
                        [
                            'payload' => 'some reply',
                            'contentType' => 'text/plain',
                            'ext' => 'response-specific'
                        ]
                    );
                });
            });

            $this->it('should error on invalid credentials (key)', function () {
                $this->assertThrowsWithMessage(ServerException::class, 'Invalid credentials', function () {
                    (new Server)->header(
                        [
                            'id' => '123456',
                            'algorithm' => 'sha256',
                            'user' => 'steve'
                        ],
                        [
                            'method' => 'POST',
                            'host' => 'example.com',
                            'port' => '8080',
                            'resource' => '/resource/4?filter=a',
                            'ts' => '1398546787',
                            'nonce' => 'xUwusx',
                            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                            'ext' => 'some-app-data',
                            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                            'id' => '123456'
                        ],
                        [
                            'payload' => 'some reply',
                            'contentType' => 'text/plain',
                            'ext' => 'response-specific'
                        ]
                    );
                });
            });

            $this->it('should error on invalid algorithm', function () {
                $this->assertThrowsWithMessage(ServerException::class, 'Unknown algorithm', function () {
                    (new Server)->header(
                        [
                            'id' => '123456',
                            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                            'algorithm' => 'x',
                            'user' => 'steve'
                        ],
                        [
                            'method' => 'POST',
                            'host' => 'example.com',
                            'port' => '8080',
                            'resource' => '/resource/4?filter=a',
                            'ts' => '1398546787',
                            'nonce' => 'xUwusx',
                            'hash' => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                            'ext' => 'some-app-data',
                            'mac' => 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                            'id' => '123456'
                        ],
                        [
                            'payload' => 'some reply',
                            'contentType' => 'text/plain',
                            'ext' => 'response-specific'
                        ]
                    );
                });
            });
        });
    }

    /**
     * @return void
     */
    public function testAuthenticateBewit()
    {
        $this->describe('Server::authenticateBewit()', function () {

            $this->it('should error on URI being too long', function () {
                $longUrl = '/';

                for ($i=0; $i < 5000; $i++) {
                    $longUrl .= 'x';
                }

                try {
                    (new Server)->authenticateBewit(
                        [
                            'method' => 'GET',
                            'url' => $longUrl,
                            'host' => 'example.com',
                            'port' => 8080
                        ],
                        function ($id) {
                            return $this->credentialsFunc($id);
                        },
                        []
                    );
                } catch (BadRequestException $e) {
                    expect($e->getMessage())->toEqual('Resource path exceeds max length');
                    expect($e->getCode())->toEqual(400);

                    return;
                }

                $this->fail('The expected exception was not thrown.');
            });

            $this->it('should error on empty bewit', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Empty bewit',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a&bewit=',
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on invalid method', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Invalid method',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'POST',
                                'url' => '/resource/4?filter=a'
                                         . '&bewit=MTIzNDU2XDE1MjkwNTA2NTBceXRMYTJPU1d5ZkdVdk93RjZZUzNKa3BuSElzPVw',
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on multiple authentications', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Multiple authentications',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a'
                                         . '&bewit=MTIzNDU2XDE1MjkwNTA2NTBceXRMYTJPU1d5ZkdVdk93RjZZUzNKa3BuSElzPVw',
                                'host' => 'example.com',
                                'port' => 8080,
                                'authorization' => 'Hawk id="1", ts="1353788437", nonce="k3j4h2"'
                                                 . ', mac="zy79QQ5/EYFmQqutVnYb73gAc/U=", ext="hello"'
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on invalid characters in bewit', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid bewit encoding',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a'
                                         . '&bewit=|MTIzNDU2XDE1MjkwNTA2NTBceXRMYTJPU1d5ZkdVdk93RjZZUzNKa3BuSElzPVw',
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on invalid bewit structure', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid bewit structure',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a'
                                         . '&bewit=MTIzNDU2XDE1MjkwNTA2NTBceXRMYTJPU1d5ZkdVdk93RjZZUzNKa3BuSElzPQ',
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on missing bewit attributes', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Missing bewit attributes',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a'
                                         . '&bewit=MTIzNDU2XFx5dExhMk9TV3lmR1V2T3dGNllTM0prcG5ISXM9XA',
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on expired bewit', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Access expired',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a'
                                         . '&bewit=MTIzNDU2XDE1MjkwNTA2NTBceXRMYTJPU1d5ZkdVdk93RjZZUzNKa3BuSElzPVw',
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on missing credentials', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Unknown credentials',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a' .
                                    '&bewit=' . (new Client)->getBewit(
                                        'http://example.net/somewhere/over/the/rainbow',
                                        [
                                            'ttlSec' => 60,
                                            'credentials' => [
                                                'id' => '123456',
                                                'key' => '2983d45yun89q',
                                                'algorithm' => 'sha1'
                                            ]
                                        ]
                                    ),
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return null;
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on invalid credentials (key)', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Invalid credentials',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a' .
                                    '&bewit=' . (new Client)->getBewit(
                                        'http://example.net/somewhere/over/the/rainbow',
                                        [
                                            'ttlSec' => 60,
                                            'credentials' => [
                                                'id' => '123456',
                                                'key' => '2983d45yun89q',
                                                'algorithm' => 'sha1'
                                            ]
                                        ]
                                    ),
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return [
                                    'id' => '123456',
                                    'algorithm' => 'sha1',
                                    'user' => 'steve'
                                ];
                            },
                            []
                        );
                    }
                );
            });

            $this->it('should error on invalid algorithm', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Unknown algorithm',
                    function () {
                        (new Server)->authenticateBewit(
                            [
                                'method' => 'GET',
                                'url' => '/resource/4?filter=a' .
                                    '&bewit=' . (new Client)->getBewit(
                                        'http://example.net/somewhere/over/the/rainbow',
                                        [
                                            'ttlSec' => 60,
                                            'credentials' => [
                                                'id' => '123456',
                                                'key' => '2983d45yun89q',
                                                'algorithm' => 'sha1'
                                            ]
                                        ]
                                    ),
                                'host' => 'example.com',
                                'port' => 8080
                            ],
                            function ($id) {
                                return [
                                    'id' => '123456',
                                    'key' => '2983d45yun89q',
                                    'algorithm' => 'x',
                                    'user' => 'steve'
                                ];
                            },
                            []
                        );
                    }
                );
            });
        });
    }

    /**
     * @return void
     */
    public function testAuthenticateMessage()
    {
        $this->describe('Server::authenticateMessage()', function () {

            $this->it('should error on invalid authorization (ts)', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid authorization',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );
                        unset($auth['ts']);

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            }
                        );
                    }
                );
            });

            $this->it('should error on invalid authorization (nonce)', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid authorization',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );
                        unset($auth['nonce']);

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            }
                        );
                    }
                );
            });

            $this->it('should error on invalid authorization (hash)', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid authorization',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );
                        unset($auth['hash']);

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            }
                        );
                    }
                );
            });

            $this->it('should generate an authorization then successfully parse it', function () {
                $auth = (new Client)->message(
                    'example.com',
                    8080,
                    'some message',
                    [
                        'credentials' => $this->credentialsFunc('123456')
                    ]
                );

                $credentials = (new Server)->authenticateMessage(
                    'example.com',
                    8080,
                    'some message',
                    $auth,
                    function ($id) {
                        return $this->credentialsFunc($id);
                    }
                )['credentials'];

                expect($credentials['user'])->toEqual('steve');
            });

            $this->it('should fail authorization on mismatching host', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Bad MAC',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );

                        (new Server)->authenticateMessage(
                            'example1.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            }
                        );
                    }
                );
            });

            $this->it('should fail authorization on stale timestamp', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Stale timestamp',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'localtimeOffsetMsec' => 100000
                            ]
                        );
                    }
                );
            });

            $this->it('should override timestampSkewSec', function () {
                $auth = (new Client)->message(
                    'example.com',
                    8080,
                    'some message',
                    [
                        'credentials' => $this->credentialsFunc('123456')
                    ]
                );

                $credentials = (new Server)->authenticateMessage(
                    'example.com',
                    8080,
                    'some message',
                    $auth,
                    function ($id) {
                        return $this->credentialsFunc($id);
                    },
                    [
                        'timestampSkewSec' => 500
                    ]
                )['credentials'];

                expect($credentials['user'])->toEqual('steve');
            });

            $this->it('should fail authorization on invalid authorization', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Invalid authorization',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );
                        unset($auth['id']);

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            }
                        );
                    }
                );
            });

            $this->it('should fail authorization on bad hash', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Bad message hash',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );
                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message1',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            }
                        );
                    }
                );
            });

            $this->it('should fail authorization on nonce error', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Invalid nonce',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return $this->credentialsFunc($id);
                            },
                            [
                                'nonceFunc' => function ($key, $nonce, $ts) {
                                    throw new \Exception;
                                }
                            ]
                        );
                    }
                );
            });

            $this->it('should fail authorization on credentials error', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'kablooey',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                throw new \Exception('kablooey');
                            }
                        );
                    }
                );
            });

            $this->it('should fail authorization on missing credentials', function () {
                $this->assertThrowsWithMessage(
                    UnauthorizedException::class,
                    'Unknown credentials',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return null;
                            }
                        );
                    }
                );
            });

            $this->it('should fail authorization on invalid credentials', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Invalid credentials',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return [
                                    'user' => 'steve'
                                ];
                            }
                        );
                    }
                );
            });

            $this->it('should fail authorization on invalid credentials algorithm', function () {
                $this->assertThrowsWithMessage(
                    ServerException::class,
                    'Unknown algorithm',
                    function () {
                        $auth = (new Client)->message(
                            'example.com',
                            8080,
                            'some message',
                            [
                                'credentials' => $this->credentialsFunc('123456')
                            ]
                        );

                        (new Server)->authenticateMessage(
                            'example.com',
                            8080,
                            'some message',
                            $auth,
                            function ($id) {
                                return [
                                    'id' => '123456',
                                    'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                                    'algorithm' => 'x',
                                    'user' => 'steve'
                                ];
                            }
                        );
                    }
                );
            });
        });
    }

    /**
     * @return void
     */
    public function testAuthenticatePayloadHash()
    {
        $this->describe('Server::authenticatePayloadHash()', function () {

            $this->it('should error on incorrect hash', function () {
                $this->assertThrowsWithMessage(UnauthorizedException::class, 'Bad payload hash', function () {
                    (new Server)->authenticatePayloadHash('123456', ['hash' => 'abcdefg']);
                });
            });
        });
    }

    /**
     * Mock function that returns a set of fake credentials
     *
     * @param  string  $id
     * @return array
     */
    private function credentialsFunc($id)
    {
        return [
            'id' => $id,
            'key' => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            'algorithm' => ($id === '1' ? 'sha1' : 'sha256'),
            'user' => 'steve'
        ];
    }
}
