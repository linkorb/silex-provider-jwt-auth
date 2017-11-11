<?php

/*
 * This file is adapted from one which is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with the Symfony source code.
 */

namespace LinkORB\JwtAuth\Security\Firewall;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\SecurityEvents;

/**
 * RenewablePreAuthenticationListener implements simple proxying to an
 * authenticator whilst allowing the possibility of forgetting a previously
 * authenticated token and proceeding with authentication anew.  Adapted from
 * SimplePreAuthenticationListener by Jordi Boggiano <j.boggiano@seld.be>.
 */
class RenewablePreAuthenticationListener implements ListenerInterface
{
    private $tokenStorage;
    private $authenticationManager;
    private $providerKey;
    private $simpleAuthenticator;
    private $logger;
    private $dispatcher;

    /**
     * @param TokenStorageInterface           $tokenStorage          A TokenStorageInterface instance
     * @param AuthenticationManagerInterface  $authenticationManager An AuthenticationManagerInterface instance
     * @param string                          $providerKey
     * @param SimplePreAuthenticatorInterface $simpleAuthenticator   A SimplePreAuthenticatorInterface instance
     * @param LoggerInterface|null            $logger                A LoggerInterface instance
     * @param EventDispatcherInterface|null   $dispatcher            An EventDispatcherInterface instance
     */
    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, $providerKey, SimplePreAuthenticatorInterface $simpleAuthenticator, LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null)
    {
        if (empty($providerKey)) {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->simpleAuthenticator = $simpleAuthenticator;
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
    }

    /**
     * Handles basic authentication, allowing the possibility of forgetting a
     * previous authenticated token and proceeding with authentication anew.
     *
     * @param GetResponseEvent $event A GetResponseEvent instance
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        if (null !== $this->logger) {
            $this->logger->info('Attempting (renewable) SimplePreAuthentication.', array('key' => $this->providerKey, 'authenticator' => get_class($this->simpleAuthenticator)));
        }

        $tokenIsAlreadyInStore = false;
        if (null !== $this->tokenStorage->getToken() && !$this->tokenStorage->getToken() instanceof AnonymousToken) {
            $tokenIsAlreadyInStore = true;
        }

        //
        try {
            $token = $this->simpleAuthenticator->createToken($request, $this->providerKey);
            if ($tokenIsAlreadyInStore && null !== $token) {
                // kill the existing token and proceed with auth
                $this->tokenStorage->setToken(null);
                if (null !== $this->logger) {
                    $this->logger->debug(
                        'Deleting existing security token from the session and renewing SimplePreAuthentication.',
                        array('key' => $this->providerKey, 'authenticator' => get_class($this->simpleAuthenticator))
                    );
                }
            } elseif (null === $token) {
                // allow null to be returned to skip authentication
                return;
            }
            $token = $this->authenticationManager->authenticate($token);
            $this->tokenStorage->setToken($token);

            if (null !== $this->dispatcher) {
                $loginEvent = new InteractiveLoginEvent($request, $token);
                $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);
            }
        } catch (AuthenticationException $e) {
            if ($tokenIsAlreadyInStore) {
                return; // no credentials in the request, so keep using the existing token
            }
            $this->tokenStorage->setToken(null);

            if (null !== $this->logger) {
                $this->logger->info('SimplePreAuthentication request failed.', array('exception' => $e, 'authenticator' => get_class($this->simpleAuthenticator)));
            }

            if ($this->simpleAuthenticator instanceof AuthenticationFailureHandlerInterface) {
                $response = $this->simpleAuthenticator->onAuthenticationFailure($request, $e);
                if ($response instanceof Response) {
                    $event->setResponse($response);
                } elseif (null !== $response) {
                    throw new \UnexpectedValueException(sprintf('The %s::onAuthenticationFailure method must return null or a Response object', get_class($this->simpleAuthenticator)));
                }
            }

            return;
        }

        if ($this->simpleAuthenticator instanceof AuthenticationSuccessHandlerInterface) {
            $response = $this->simpleAuthenticator->onAuthenticationSuccess($request, $token);
            if ($response instanceof Response) {
                $event->setResponse($response);
            } elseif (null !== $response) {
                throw new \UnexpectedValueException(sprintf('The %s::onAuthenticationSuccess method must return null or a Response object', get_class($this->simpleAuthenticator)));
            }
        }
    }
}
