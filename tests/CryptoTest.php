<?php

namespace Shawm11\Hawk\Tests;

use PHPUnit\Framework\TestCase;
use Shawm11\Hawk\Crypto\Crypto;

class CryptoTest extends TestCase
{
    use \Codeception\Specify;

    /**
     * @return void
     */
    public function testGenerateNormalizedString()
    {
        $this->describe('Crypto::generateNormalizedString()', function () {
            $options = [
                'ts' => 1357747017,
                'nonce' => 'k3k4j5',
                'method' => 'GET',
                'resource' => '/resource/something',
                'host' => 'example.com',
                'port' => 8080
            ];

            $this->it('should return a valid normalized string', function () use ($options) {
                expect((new Crypto)->generateNormalizedString('header', $options))
                    ->toEqual("hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n");
            });

            $this->it('should return a valid normalized string (ext)', function () use ($options) {
                $options['ext'] = 'this is some app data';

                expect((new Crypto)->generateNormalizedString('header', $options))
                    ->toEqual(
                        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\n"
                        . "example.com\n8080\n\nthis is some app data\n"
                    );
            });

            $this->it('should return a valid normalized string (payload + ext)', function () use ($options) {
                $options['hash'] = 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=';
                $options['ext'] = 'this is some app data';

                expect((new Crypto)->generateNormalizedString('header', $options))
                    ->toEqual(
                        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\n"
                        . "example.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\n"
                        . "this is some app data\n"
                    );
            });
        });
    }
}
