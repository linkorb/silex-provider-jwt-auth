<?php

namespace LinkORB\JwtAuth\Security\EntryPoint;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Start authentication by directing the user to a page where they may be
 * informed of the need to obtain a JWT from somewhere.
 */
class FastAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * @var string
     */
    private $infoUrl;

    /**
     * @param string $infoUrl Url which informs the user about the need for a JWT.
     */
    public function __construct($infoUrl)
    {
        $this->infoUrl = $infoUrl;
    }

    /**
     * Redirect to infoUrl.
     *
     * {@inheritDoc}
     */
    public function start(
        Request $request,
        AuthenticationException $authException = null
    ) {
        return new RedirectResponse($this->infoUrl);
    }
}
