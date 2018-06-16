<?php

namespace Shawm11\Hawk\Server;

class BadRequestException extends ServerException
{
    public function __construct($message = '', $code = 400, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
