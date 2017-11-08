<?php

namespace LinkORB\JwtAuth\Security\Authentication;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\SimplePreAuthenticatorInterface;

use LinkORB\JwtAuth\JwtCodec\EncoderException;
use LinkORB\JwtAuth\JwtCodec\JwtDecoder;

/**
 * Authenticate a User based on a claimed username presented in a Json Web Token.
 *
 * Only perform authentication when a specific path is requested, e.g. "/auth".
 *
 */
class FastJwtAuthenticator implements SimplePreAuthenticatorInterface
{
    /**
     * The name of the JWT key which holds the username being claimed.
     *
     * @var string
     */
    const TOKEN_KEY_USERNAME = 'username';
    /**
     * The name of the Request key which holds JWT.
     *
     * @var string
     */
    const REQUEST_KEY = 'jwt';
    /**
     * The path which, when requested, will use a JWT supplied in the request
     * to authenticate the requester.
     *
     * @var string
     */
    const AUTH_PATH = '/auth';

    protected $decoder;
    protected $options = [];

    public function __construct(JwtDecoder $decoder, array $options = [])
    {
        $this->decoder = $decoder;
        $this->options = $options;
    }

    /**
     * Extract the credentials from a Json Web Token in the request.
     *
     * This implementation merely obtains the jwt from the URL query string.
     *
     * {@inheritDoc}
     */
    public function createToken(Request $request, $providerKey)
    {
        if ($request->getPathInfo() !== $this->optAuthPath()) {
            return;
        }

        $encodedClaimToken = $request
            ->query
            ->get($this->optRequestKey())
        ;

        if (empty($encodedClaimToken)) {
            throw new BadCredentialsException();
        }

        return new PreAuthenticatedToken(
            'anon.',
            $encodedClaimToken,
            $providerKey
        );
    }

    /**
     * The User is authentic when the Json Web Token holds a valid username
     * claim and a User of the claimed username is successfully retrieved, with
     * its roles, from whatever User store is being used.
     *
     * {@inheritDoc}
     */
    public function authenticateToken(
        TokenInterface $token,
        UserProviderInterface $userProvider,
        $providerKey
    ) {
        $jwt = $token->getCredentials();

        try {
            $claim = $this->decoder->decode($jwt);
        } catch (EncoderException $e) {
            throw new CustomUserMessageAuthenticationException(
                'The supplied Json Web Token is invalid.'
            );
        }

        $usernameProperty = $this->optUsername();
        if (!isset($claim->{$usernameProperty})) {
            throw new CustomUserMessageAuthenticationException(
                'The supplied Json Web Token is invalid.'
            );
        }

        $username = $claim->{$usernameProperty};
        if ('' === $username || null === $username) {
            $username = AuthenticationProviderInterface::USERNAME_NONE_PROVIDED;
        }

        $user = $token->getUser();
        if ($user instanceof User) {
            $authenticToken = new PreAuthenticatedToken(
                $user,
                $jwt,
                $providerKey,
                $user->getRoles()
            );
            $authenticToken->setAttribute('claim', $claim);
            return $authenticToken;
        }

        $user = null;
        try {
            $user = $userProvider->loadUserByUsername($username);
        } catch (UsernameNotFoundException $e) {
            throw new CustomUserMessageAuthenticationException(
                'The supplied Json Web Token is invalid.'
            );
        }

        $authenticToken = new PreAuthenticatedToken(
            $user,
            $jwt,
            $providerKey,
            $user->getRoles()
        );
        $authenticToken->setAttribute('claim', $claim);
        return $authenticToken;
    }

    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof PreAuthenticatedToken
            && $token->getProviderKey() === $providerKey
        ;
    }

    protected function optUsername()
    {
        return isset($this->options['username_jwt_key'])
            ? $this->options['username_jwt_key']
            : self::TOKEN_KEY_USERNAME
        ;
    }

    protected function optRequestKey()
    {
        return isset($this->options['jwt_request_key'])
            ? $this->options['jwt_request_key']
            : self::REQUEST_KEY
        ;
    }

    protected function optAuthPath()
    {
        return isset($this->options['check_path'])
            ? $this->options['check_path']
            : self::AUTH_PATH
        ;
    }
}
