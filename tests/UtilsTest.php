<?php

namespace Shawm11\Hawk\Tests;

use PHPUnit\Framework\TestCase;
use Shawm11\Hawk\Utils\Utils;
use Shawm11\Hawk\HawkException;
use Shawm11\Hawk\Server\BadRequestException;
use Shawm11\Hawk\Server\UnauthorizedException;

class UtilsTest extends TestCase
{
    use \Codeception\Specify;
    use \Codeception\AssertThrows;

    /**
     * @return void
     */
    public function testParseAuthorizationHeader()
    {
        $this->describe('Utils::parseAuthorizationHeader()', function () {

            $this->it('should throw an error if the header is missing', function () {
                $this->assertThrowsWithMessage(UnauthorizedException::class, '', function () {
                    (new Utils)->parseAuthorizationHeader(null);
                });
            });

            $this->it('should throw an error if the header is too long', function () {
                /*
                 * Create a long string
                 */
                $tooLongHeader = 'Scheme a="';

                for ($i=0; $i < 5000; $i++) {
                    $tooLongHeader .= 'x';
                }

                $tooLongHeader .= '"';

                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Header length too long',
                    function () use ($tooLongHeader) {
                        (new Utils)->parseAuthorizationHeader($tooLongHeader, ['a']);
                    }
                );
            });

            $this->it('should throw an error if the header does not have the correct syntax', function () {
                $this->assertThrowsWithMessage(BadRequestException::class, 'Invalid header syntax', function () {
                    (new Utils)->parseAuthorizationHeader('???');
                });
            });

            $this->it('should throw an error if the header is not a Hawk header', function () {
                $this->assertThrowsWithMessage(UnauthorizedException::class, '', function () {
                    (new Utils)->parseAuthorizationHeader('Not a Hawk header');
                });
            });

            $this->it('should throw an error if the header is invalid', function () {
                $this->assertThrowsWithMessage(BadRequestException::class, 'Invalid header syntax', function () {
                    (new Utils)->parseAuthorizationHeader('hawk');
                });
            });

            $this->it('should throw an error if the header contains an unknown attribute', function () {
                $this->assertThrowsWithMessage(BadRequestException::class, 'Unknown attribute: foo', function () {
                    (new Utils)->parseAuthorizationHeader('hawk foo="bar"');
                });
            });

            $this->it(
                'should throw an error if the header contains attributes with characters that are not allowed',
                function () {
                    $this->assertThrowsWithMessage(BadRequestException::class, 'Bad attribute value: foo', function () {
                        (new Utils)->parseAuthorizationHeader('hawk foo="bär"', ['foo']);
                    });
                }
            );

            $this->it('should throw an error if the header contains duplicate attributes', function () {
                $this->assertThrowsWithMessage(
                    BadRequestException::class,
                    'Duplicate attribute: foo',
                    function () {
                        (new Utils)->parseAuthorizationHeader('hawk foo="bar", foo="baz"', ['foo']);
                    }
                );
            });
        });
    }

    /**
     * @return void
     */
    public function testEscapeHeaderAttribute()
    {
        $this->describe('Utils::escapeHeaderAttribute()', function () {
            $this->it(
                'should throw error if the header attribute contains a character that is not allowed',
                function () {
                    $this->assertThrowsWithMessage(HawkException::class, 'Bad attribute value (bär)', function () {
                        (new Utils)->escapeHeaderAttribute('bär');
                    });
                }
            );
        });
    }
}
