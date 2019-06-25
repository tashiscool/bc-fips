package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;

/**
 * Container class for Diffie-Hellman domain parameters.
 */
public class DHDomainParameters
{
    private static final int DEFAULT_MINIMUM_LENGTH = 160;

    private final BigInteger g;
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger j;
    private final int        m;
    private final int        l;
    private final DHValidationParameters validation;

    private static int getDefaultMParam(
        int lParam)
    {
        if (lParam == 0)
        {
            return DEFAULT_MINIMUM_LENGTH;
        }

        return lParam < DEFAULT_MINIMUM_LENGTH ? lParam : DEFAULT_MINIMUM_LENGTH;
    }

    /**
     *  Minimal usable parameters.
     *
     * @param p the prime p defining the Galois field.
     * @param g the generator of the multiplicative subgroup of order g.
     */
    public DHDomainParameters(
        BigInteger  p,
        BigInteger  g)
    {
        this(p, null, g, 0);
    }

    /**
     * Minimal usable parameters with a private value length (PKCS#3).
     *
     * @param p the prime p defining the Galois field.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param l the maximum bit length for the private value.
     */
    public DHDomainParameters(
        BigInteger  p,
        BigInteger  g,
        int         l)
    {
        this(p, null, g, l);
    }

    /**
     * Minimal constructor for parameters able to be used to verify a public key.
     *
     * @param p the prime p defining the Galois field.
     * @param q specifies the prime factor of p - 1.
     * @param g the generator of the multiplicative subgroup of order g.
     */
    public DHDomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g)
    {
        this(p, q, g, 0);
    }

    /**
     * Minimal constructor for parameters able to be used to verify a public key with a private value length.
     *
     * @param p the prime p defining the Galois field.
     * @param q specifies the prime factor of p - 1.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param l the maximum bit length for the private value.
     */
    public DHDomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        int l)
    {
        this(p, q, g, getDefaultMParam(l), l, null, null);
    }

    /**
     * Parameters which can verify a public key with private value lengths.
     *
     * @param p the prime p defining the Galois field.
     * @param q specifies the prime factor of p - 1.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param m the minimum bit length for the private value.
     * @param l the maximum bit length for the private value.
     */
    public DHDomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        int m,
        int l)
    {
        this(p, q, g, m, l, null, null);
    }

    /**
     * Standard constructor - the full X9.42 parameter set.
     *
     * @param p the prime p defining the Galois field.
     * @param q specifies the prime factor of p - 1.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param j optionally specifies the value that satisfies the equation p = jq+1
     * @param validation parameters for validating these domain parameters.
     */
    public DHDomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        BigInteger j,
        DHValidationParameters validation)
    {
        this(p, q, g, DEFAULT_MINIMUM_LENGTH, 0, j, validation);
    }

    /**
     * X9.42 parameters with private value length.
     *
     * @param p the prime p defining the Galois field.
     * @param q specifies the prime factor of p - 1.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param l the maximum bit length for the private value.
     * @param validation parameters for validating these domain parameters.
     */
    public DHDomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        int l,
        DHValidationParameters validation)
    {
        this(p, q, g, getDefaultMParam(l), l, null, validation);
    }

    /**
     * Base constructor - the full domain parameter set.
     *
     * @param p the prime p defining the Galois field.
     * @param q specifies the prime factor of p - 1.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param m the minimum bit length for the private value.
     * @param l the maximum bit length for the private value.
     * @param j optionally specifies the value that satisfies the equation p = jq+1
     * @param validation parameters for validating these domain parameters.
     */
    public DHDomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        int m,
        int l,
        BigInteger j,
        DHValidationParameters validation)
    {
        if (l != 0)
        {
            BigInteger bigL = BigInteger.valueOf(2L ^ (l - 1));
            if (bigL.compareTo(p) == 1)
            {
                throw new IllegalArgumentException("when l value specified, it must satisfy 2^(l-1) <= p");
            }
            if (l < m)
            {
                throw new IllegalArgumentException("when l value specified, it may not be less than m value");
            }
        }

        this.g = g;
        this.p = p;
        this.q = q;
        this.m = m;
        this.l = l;
        this.j = j;
        this.validation = validation;
    }

    /**
     * Return the prime p defining the Galois field.
     *
     * @return the prime p.
     */
    public BigInteger getP()
    {
        return p;
    }

    /**
     * Return the generator of the multiplicative subgroup of order g.
     *
     * @return the generator g.
     */
    public BigInteger getG()
    {
        return g;
    }

    /**
     * Return q, the prime factor of p - 1
     *
     * @return q value
     */
    public BigInteger getQ()
    {
        return q;
    }

    /**
     * Return the subgroup factor J, which satisifes the equation p=jq+1, if present.
     *
     * @return subgroup factor, or null.
     */
    public BigInteger getJ()
    {
        return j;
    }

    /**
     * Return the minimum length of the private value.
     *
     * @return the minimum length of the private value in bits.
     */
    public int getM()
    {
        return m;
    }

    /**
     * Return the private value length in bits - if set, zero otherwise
     *
     * @return the private value length in bits, zero otherwise.
     */
    public int getL()
    {
        return l;
    }

    public DHValidationParameters getValidationParameters()
    {
        return validation;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DHDomainParameters))
        {
            return false;
        }

        DHDomainParameters    pm = (DHDomainParameters)obj;

        return pm.getP().equals(p) && pm.getG().equals(g);
    }
    
    public int hashCode()
    {
        return getP().hashCode() ^ getG().hashCode();
    }
}
