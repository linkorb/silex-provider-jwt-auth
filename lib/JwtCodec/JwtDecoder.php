<?php

namespace LinkORB\JwtAuth\JwtCodec;

use UnexpectedValueException;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

/**
 * Decode a Json Web Token using the Firebase JWT library.
 *
 */
class JwtDecoder
{
    /**
     * Key for decoding.
     *
     * This is the public key when using asymetric algorithms.
     *
     * @var string|array
     */
    private $key;

    /**
     * List of permitted algorithm identifiers.
     *
     * @var string
     */
    private $allowedAlgos;

    /**
     * @param string|array $key for decoding
     * @param array $allowedAlgos list of permitted algorithm identifiers
     */
    public function __construct($key, array $allowedAlgos)
    {
        $this->key = $key;
        $this->allowedAlgos = $allowedAlgos;
    }

    /**
     * Decode a JWT.
     *
     * @param string $token
     * @return object
     *
     * @throws \LinkORB\Security\Encoder\EncoderException
     */
    public function decode($token)
    {
        try {
            return JWT::decode($token, $this->key, $this->allowedAlgos);
        } catch (UnexpectedValueException $e) {
            throw new EncoderException('The token cannot be decoded.', null, $e);
        } catch (SignatureInvalidException $e) {
            throw new EncoderException('The token cannot be verified.', null, $e);
        } catch (BeforeValidException $e) {
            throw new EncoderException('The token is not yet valid.', null, $e);
        } catch (ExpiredException $e) {
            throw new EncoderException('The token is no longer valid.', null, $e);
        }
    }
}
