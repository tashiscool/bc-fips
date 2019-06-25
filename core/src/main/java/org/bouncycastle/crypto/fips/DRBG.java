/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

/**
 * Interface to SP800-90A/X9.31 deterministic random bit generators.
 */
interface DRBG
{
    /**
     * Return the block size of the DRBG.
     *
     * @return the block size (in bits) produced by each round of the DRBG.
     */
    int getBlockSize();

    /**
     * Return the security strength of the DRBG.
     *
     * @return the security strength (in bits) of the DRBG.
     */
    int getSecurityStrength();

    /**
     * Populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param additionalInput additional input to be added to the DRBG in this step.
     * @param predictionResistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    int generate(byte[] output, byte[] additionalInput, boolean predictionResistant);

    /**
     * Reseed the DRBG.
     *
     * @param additionalInput additional input to be added to the DRBG in this step.
     */
    void reseed(byte[] additionalInput);

    /**
     * Return a KAT for the DRBG - used prior to initialisation.
     * @param algorithm the FipsAlgorithm type
     * @return a self test
     */
    VariantInternalKatTest createSelfTest(FipsAlgorithm algorithm);

    /**
     * Return a KAT for the DRBG - used prior to reseed.
     * @param algorithm the FipsAlgorithm type
     * @return a self test
     */
    VariantInternalKatTest createReseedSelfTest(FipsAlgorithm algorithm);
}
