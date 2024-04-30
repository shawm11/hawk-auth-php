<?php

/*
 * NOTICE
 *
 * This example will not work without modification. However, this example should
 * be enough to demonstrate how to use Hawk as a server.
 */

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