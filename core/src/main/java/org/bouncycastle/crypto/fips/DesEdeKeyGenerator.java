package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DesEdeParameters;
import org.bouncycastle.crypto.internal.params.DesParameters;

class DesEdeKeyGenerator
    extends CipherKeyGenerator
{
    private final FipsAlgorithm algorithm;

    public DesEdeKeyGenerator(FipsAlgorithm algorithm)
    {
        this.algorithm = algorithm;
    }

    /**
     * initialise the key generator - if strength is set to zero
     * the key generated will be 192 bits in size, otherwise
     * strength can be 128 or 192 (or 112 or 168 if you don't count
     * parity bits), depending on whether you wish to do 2-key or 3-key
     * triple DES.
     *
     * @param param the parameters to be used for key generation
     */
    public void init(
        KeyGenerationParameters param)
    {
        this.random = param.getRandom();
        this.strength = (param.getStrength() + 7) / 8;

        if (strength == 0 || strength == (168 / 8))
        {
            strength = DesEdeParameters.DES_EDE_KEY_LENGTH;
        }
        else if (strength == (112 / 8))
        {
            strength = 2 * DesParameters.DES_KEY_LENGTH;
        }
        else if (strength != DesEdeParameters.DES_EDE_KEY_LENGTH
                && strength != (2 * DesParameters.DES_KEY_LENGTH))
        {
            throw new IllegalArgumentException("Key must be "
                + (DesEdeParameters.DES_EDE_KEY_LENGTH * 8) + " or "
                + (2 * 8 * DesParameters.DES_KEY_LENGTH)
                + " bits long: " + algorithm.getName());
        }
    }

    public byte[] generateKey()
    {
        byte[]  newKey = new byte[strength];
        int count = 0;

        do
        {
            random.nextBytes(newKey);

            DesParameters.setOddParity(newKey);
        }
        while (DesEdeParameters.isWeakKey(newKey, 0, newKey.length) && !DesEdeParameters.isRealEDEKey(newKey) && count++ < 10);

        if (DesEdeParameters.isWeakKey(newKey, 0, newKey.length) || !DesEdeParameters.isRealEDEKey(newKey))
        {
            // if this happens there's got to be something terribly wrong.
            throw new FipsOperationError("Failed to generate a valid TripleDES key: " + algorithm.getName());
        }

        return newKey;
    }
}
