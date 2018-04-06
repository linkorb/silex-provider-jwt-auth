<?php

namespace LinkORB\JwtAuth\Security\Authentication;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

use LinkORB\JwtAuth\JwtCodec\JwtDecoder;

/**
 * Redirect to the originally requested path (target_path) once authentication
 * succeeds.
 */
class JwtAuthenticator extends FastJwtAuthenticator implements
    AuthenticationSuccessHandlerInterface,
    AuthenticationFailureHandlerInterface
{
    /**
     * The default URL path to which to redirect post-authentication.
     *
     * @var string
     */
    const DEFAULT_REDIRECT = '/';

    public function __construct(JwtDecoder $decoder, array $options = [])
    {
        parent::__construct($decoder, $options);
    }

    /**
     * Resolve targetUrl and redirect
     * 
     * Resolves targetUrl in following order:
     * 1. a `target` passed as HTTP Query parameter
     * 2. the session target_path, as was set at start of authentication.
     * 3. the default redirect option
     *
     * {@inheritDoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $targetUrl = null;
        if ($request->query->has('target')) {
            $targetUrl = $request->getSchemeAndHttpHost() . $request->query->get('target');
        }
        if (!$targetUrl) {
            $targetUrl = $request->getSession()->get("_security.{$token->getProviderKey()}.target_path");
        }
        if (!$targetUrl) {
            $targetUrl = $request->getSchemeAndHttpHost() . $this->optDefaultRedirect();
        }

        return new RedirectResponse($targetUrl);
    }

    /**
     * Return 401.
     *
     * {@inheritDoc}
     */
    public function onAuthenticationFailure(
        Request $request,
        AuthenticationException $exception
    ) {
        return new Response(
            strtr($exception->getMessageKey(), $exception->getMessageData()),
            401
        );
    }

    private function optDefaultRedirect()
    {
        return isset($this->options['default_return_to'])
            ? $this->options['default_return_to']
            : self::DEFAULT_REDIRECT
        ;
    }
}
