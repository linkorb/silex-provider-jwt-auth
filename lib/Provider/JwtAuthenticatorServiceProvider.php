<?php

namespace LinkORB\JwtAuth\Provider;

use RuntimeException;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Api\BootableProviderInterface;
use Silex\Api\ControllerProviderInterface;
use Silex\Application;
use Symfony\Component\Security\Core\Authentication\Provider\SimpleAuthenticationProvider;
use Symfony\Component\Security\Http\Firewall\SimplePreAuthenticationListener;

use LinkORB\JwtAuth\JwtCodec\JwtDecoder;
use LinkORB\JwtAuth\Security\Authentication\JwtAuthenticator;
use LinkORB\JwtAuth\Security\EntryPoint\JwtAuthenticationEntryPoint;

/**
 * Provides a Json Web Token (JWT) decoder and a "jwt_issuer" firewall which
 * sends users to an issuer of JWTs to claim a username for authentication.
 *
 * The intention is to direct the user to a particular URL where they will be
 * prompted to sign-in before being issued a token and directed back to the app
 * check_path where authentication will continue.  If the token is valid the
 * user is returned to their original location in the app.
 *
 * Mandatory configuration (jwt_auth.decoder.config):-
 *
 * decoder_key: a closure which returns the symmetric key or public assymetric
 *              key material (or a map of key ids to keys) with which to decode
 *              the JWTs
 * permitted_algos: list of permitted algorithm identifiers
 *
 * Firewall options:-
 *
 * app_identifier: Required! An identifier for the application.
 * jwt_issuer_url: Required! Url from where a Json Web Token may be obtained.
 *
 * jwt_issuer_url_origin_param: The name of an HTTP query string parameter with
 *                              which to supply the issuer with the origin path
 *                              (i.e. the path originally requested by the user)
 * default_return_to: path to which to redirect after successful authentication
 *                    (used only when the JWT does not contain this information,
 *                    default: "/")
 * username_jwt_key: the name of a key in the JWT which holds the username
 *                   being claimed (default: "username")
 * jwt_request_key: the name of an HTTP query string parameter which holds the
 *                  JWT (default: jwt)
 * check_path: the path at which the JWT is decoded and used for authentication
 *             (default: "/auth")
 *
 */
class JwtAuthenticatorServiceProvider implements
    ServiceProviderInterface,
    ControllerProviderInterface,
    BootableProviderInterface
{
    private $fakeRoutes = [];

    public function register(Container $app)
    {
        $app['jwt_auth.decoder'] = function () use ($app) {
            if (!isset($app['jwt_auth.decoder.config'])) {
                throw new RuntimeException('Missing configuration "jwt_auth.decoder.config".');
            }
            if (!isset($app['jwt_auth.decoder.config']['decoder_key'])) {
                throw new RuntimeException('Missing "decoder_key" from configuration "jwt_auth.decoder.config".');
            }
            if (!isset($app['jwt_auth.decoder.config']['permitted_algos'])) {
                throw new RuntimeException('Missing "permitted_algos" from configuration "jwt_auth.decoder.config".');
            }
            return new JwtDecoder(
                $app['jwt_auth.decoder.config']['decoder_key'](), // closure
                $app['jwt_auth.decoder.config']['permitted_algos']
            );
        };

        $that = $this;

        // https://silex.sensiolabs.org/doc/2.0/providers/security.html#defining-a-custom-authentication-provider
        //
        $app['security.authentication_listener.factory.jwt_issuer'] = $app->protect(function ($name, $options) use ($app, $that) {
            if (!isset($options['app_identifier'])) {
                throw new RuntimeException("Missing option \"app_identifier\" for firewall {$name}.");
            }
            if (!isset($options['jwt_issuer_url'])) {
                throw new RuntimeException("Missing option \"jwt_issuer_url\" for firewall {$name}.");
            }
            $app["jwt_auth.security.entry_point.{$name}.jwt_issuer"] = function () use ($app, $options) {
                return new JwtAuthenticationEntryPoint(
                    $options['app_identifier'],
                    $options['jwt_issuer_url'],
                    $options
                );
            };

            $that->addFakeRoute(
                'get',
                isset($options['check_path']) ? $options['check_path'] : JwtAuthenticator::AUTH_PATH,
                "check_path_{$name}"
            );
            $app["jwt_auth.security.authenticator.{$name}.jwt_issuer"] = function () use ($app, $options) {
                return new JwtAuthenticator(
                    $app['jwt_auth.decoder'],
                    $options
                );
            };
            $app["security.authentication_provider.{$name}.jwt_issuer"] = function () use ($app, $name) {
                return new SimpleAuthenticationProvider(
                    $app["jwt_auth.security.authenticator.{$name}.jwt_issuer"],
                    $app['security.user_provider.'.$name],
                    $name
                );
            };
            $app["security.authentication_listener.{$name}.jwt_issuer"] = function () use ($app, $name) {
                return new SimplePreAuthenticationListener(
                    $app['security.token_storage'],
                    $app['security.authentication_manager'],
                    $name,
                    $app["jwt_auth.security.authenticator.{$name}.jwt_issuer"],
                    isset($app['logger']) ? $app['logger'] : null,
                    $app['dispatcher']
                );
            };
            return array(
                "security.authentication_provider.{$name}.jwt_issuer",
                "security.authentication_listener.{$name}.jwt_issuer",
                "jwt_auth.security.entry_point.{$name}.jwt_issuer",
                'pre_auth'
            );
        });
    }

    public function connect(Application $app)
    {
        $controllers = $app['controllers_factory'];
        foreach ($this->fakeRoutes as $route) {
            list($method, $pattern, $name) = $route;

            $controllers->$method($pattern)->run(null)->bind($name);
        }

        return $controllers;
    }

    public function boot(Application $app)
    {
        $app->mount('/', $this->connect($app));
    }

    public function addFakeRoute($method, $pattern, $name)
    {
        $this->fakeRoutes[] = array($method, $pattern, $name);
    }
}
