<?php

namespace LinkORB\JwtAuth\Security\EntryPoint;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\HttpUtils;

/**
 * Start authentication by directing the user to a page where they may be
 * informed of the need to obtain a JWT from somewhere.
 */
class FastAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     *
     * @var HttpUtils
     */
    private $httpUtils;
    /**
     * @var string
     */
    private $infoUrl;

    /**
     * @param HttpUtils $httpUtils  An HttpUtils instance
     * @param string $infoUrl Url or path to a page which informs the user about
     *                        the need for a JWT.
     */
    public function __construct(HttpUtils $httpUtils, $infoUrl)
    {
        $this->httpUtils = $httpUtils;
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
        return $this->httpUtils->createRedirectResponse($request, $this->infoUrl);
    }
}
