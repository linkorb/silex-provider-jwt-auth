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
     * Redirect to the session target_path, as was set at start of authentication.
     *
     * {@inheritDoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $targetUrl = $request->getSession()->get("_security.{$token->getProviderKey()}.target_path");
        if (!$targetUrl) {
            return new RedirectResponse(
                $request->getSchemeAndHttpHost() . $this->optDefaultRedirect()
            );
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
