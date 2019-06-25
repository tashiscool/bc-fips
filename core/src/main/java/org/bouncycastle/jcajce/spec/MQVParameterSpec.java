package org.bouncycastle.jcajce.spec;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec to provide MQV ephemeral keys and user keying material.
 */
public class MQVParameterSpec
    implements AlgorithmParameterSpec
{
    private final PublicKey ephemeralPublicKey;
    private final PrivateKey ephemeralPrivateKey;
    private final PublicKey otherPartyEphemeralKey;
    private final byte[] userKeyingMaterial;

    /**
     * Base constructor.
     *
     * @param ephemeralPublicKey our ephemeral public key.
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the other party's ephemeral public key.
     * @param userKeyingMaterial the user keying material for the key derivation function.
     */
    public MQVParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
    }

    /**
     * Constructor without user keying material.
     *
     * @param ephemeralPublicKey our ephemeral public key.
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the other party's ephemeral public key.
     */
    public MQVParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
    }

    /**
     * Constructor taking an ephemeral key pair.
     *
     * @param ephemeralKeyPair keypair holding our ephemeral public and private keys.
     * @param otherPartyEphemeralKey the other party's ephemeral public key.
     * @param userKeyingMaterial the user keying material for the key derivation function.
     */
    public MQVParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, userKeyingMaterial);
    }

    /**
     * Constructor without our ephemeral public key - in this case it is assumed the ephemeral public key can be calculated
     * later.
     *
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the other party's ephemeral public key.
     * @param userKeyingMaterial the user keying material for the key derivation function.
     */
    public MQVParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(null, ephemeralPrivateKey, otherPartyEphemeralKey, userKeyingMaterial);
    }

    /**
     * Constructor taking an ephemeral key pair without user keying material.
     *
     * @param ephemeralKeyPair keypair holding our ephemeral public and private keys.
     * @param otherPartyEphemeralKey the other party's ephemeral public key.
     */
    public MQVParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, null);
    }

    /**
     * Constructor without our ephemeral public key or user keying material - in this case it is assumed the ephemeral
     * public key can be calculated later.
     *
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the other party's ephemeral public key.
     */
    public MQVParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
    {
        this(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
    }

    /**
     * Return our ephemeral private key.
     *
     * @return our ephemeral private key.
     */
    public PrivateKey getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    /**
     * Return our ephemeral public key, if available.
     *
     * @return the ephemeral public key, may be null.
     */
    public PublicKey getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }

    /**
     * Return the other party's ephemeral public key.
     *
     * @return the other party's public key.
     */
    public PublicKey getOtherPartyEphemeralKey()
    {
        return otherPartyEphemeralKey;
    }

    /**
     * Return the user keying material for the KDF used to derive the final secret key.
     *
     * @return the user keying material to be input into the KDF.
     */
    public byte[] getUserKeyingMaterial()
    {
        return Arrays.clone(userKeyingMaterial);
    }
}
