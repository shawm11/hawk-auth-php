<?php

/*
 * NOTICE
 *
 * This example will not work without modification. However, this example should
 * be enough to demonstrate how to use Hawk as a client.
 */

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