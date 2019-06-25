/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal;

import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;

/**
 * a holding class for public/private parameter pairs.
 */
public class AsymmetricCipherKeyPair
{
    private AsymmetricKeyParameter    publicParam;
    private AsymmetricKeyParameter    privateParam;

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
     */
    public AsymmetricCipherKeyPair(
        AsymmetricKeyParameter    publicParam,
        AsymmetricKeyParameter    privateParam)
    {
        this.publicParam = publicParam;
        this.privateParam = privateParam;
    }

    /**
     * return the public key parameters.
     *
     * @return the public key parameters.
     */
    public AsymmetricKeyParameter getPublic()
    {
        return publicParam;
    }

    /**
     * return the private key parameters.
     *
     * @return the private key parameters.
     */
    public AsymmetricKeyParameter getPrivate()
    {
        return privateParam;
    }
}
