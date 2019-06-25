package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.EntropySource;

class DRBGPseudoRandom
    implements DRBG
{
    private final FipsAlgorithm algorithm;
    private final DRBGProvider drbgProvider;
    private final EntropySource entropySource;

    private DRBG drbg;

    DRBGPseudoRandom(FipsAlgorithm algorithm, EntropySource entropySource, DRBGProvider drbgProvider)
    {
        this.algorithm = algorithm;
        this.entropySource = new ContinuousTestingEntropySource(entropySource);
        this.drbgProvider = drbgProvider;
    }

    /**
     * Return the block size of the underlying DRBG
     *
     * @return number of bits produced each cycle.
     */
    public int getBlockSize()
    {
        synchronized (this)
        {
            lazyInitDRBG();
        }

        return drbg.getBlockSize();
    }

    public int getSecurityStrength()
    {
        synchronized (this)
        {
            lazyInitDRBG();
        }

        return drbg.getSecurityStrength();
    }

    private void lazyInitDRBG()
    {
        if (drbg == null)
        {
            drbg = drbgProvider.get(entropySource);
            // FSM_TRANS:5.5, "CONDITIONAL TEST", "DRBG HEALTH CHECKS", "Invoke DRBG Health Check"
            SelfTestExecutor.validate(algorithm, drbg.createSelfTest(algorithm));   // instance health test
            // FSM_TRANS:5.6, "DRBG HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Health Check successful"
        }
    }

    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            // if predictionResistant a reseed will be performed at the start of generate.
            if (predictionResistant)
            {
                // FSM_STATE:5.8, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
                // FSM_TRANS:5.11, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));    // reseed health test
                // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                // FSM_TRANS:5.13, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"
            }

            // check if a reseed is required...
            if (drbg.generate(output, additionalInput, predictionResistant) < 0)
            {
                // FSM_STATE:5.8, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
                // FSM_TRANS:5.11, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));    // reseed health test
                // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                // FSM_TRANS:5.13, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"

                drbg.reseed(null);
                return drbg.generate(output, additionalInput, predictionResistant);
            }

            return output.length;
        }
    }

    public void reseed(byte[] additionalInput)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            // FSM_STATE:5.8, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
            // FSM_TRANS:5.11, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
            SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));   // reseed health test.
            // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
            // FSM_TRANS:5.13, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"

            drbg.reseed(additionalInput);
        }
    }

    public VariantInternalKatTest createSelfTest(FipsAlgorithm algorithm)
    {
        return drbg.createSelfTest(algorithm);
    }

    public VariantInternalKatTest createReseedSelfTest(FipsAlgorithm algorithm)
    {
        return drbg.createReseedSelfTest(algorithm);
    }

    /*
    // Test for use of reseed self tests and basic self test.
    private static void check(String msg, boolean condition)
    {
        if (!condition)
        {
            System.err.println(msg);
        }
    }

    public static void main(String[] args)
    {
        final java.util.concurrent.atomic.AtomicInteger selfTestCount = new java.util.concurrent.atomic.AtomicInteger(0);
        final java.util.concurrent.atomic.AtomicInteger reseedTestCount = new java.util.concurrent.atomic.AtomicInteger(0);

        DRBG testDrbg = new DRBGPseudoRandom(FipsDRBG.SHA1.getAlgorithm(),
            new EntropySource()
            {
                public boolean isPredictionResistant()
                {
                    return false;
                }

                public byte[] getEntropy()
                {
                    return new byte[0];
                }

                public int entropySize()
                {
                    return 0;
                }
            },
            new DRBGProvider()
            {
                public DRBG get(EntropySource entropySource)
                {
                    return new DRBG()
                    {
                        boolean isFirst = true;

                        public int getBlockSize()
                        {
                            return 20;
                        }

                        public int getSecurityStrength()
                        {
                            return 128;
                        }

                        public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
                        {
                            if (isFirst)
                            {
                                isFirst = false;
                            }
                            else
                            {
                                // second call with false should trigger reseed
                                if (!predictionResistant)
                                {
                                    return -1;
                                }
                            }
                            return 0;
                        }

                        public void reseed(byte[] additionalInput)
                        {

                        }

                        public VariantInternalKatTest createSelfTest(FipsAlgorithm algorithm)
                        {
                            return new VariantInternalKatTest(FipsDRBG.SHA1.getAlgorithm())
                            {
                                @Override
                                void evaluate()
                                    throws Exception
                                {
                                    selfTestCount.incrementAndGet();
                                }
                            };
                        }

                        public VariantInternalKatTest createReseedSelfTest(FipsAlgorithm algorithm)
                        {
                            return new VariantInternalKatTest(FipsDRBG.SHA1.getAlgorithm())
                            {
                                @Override
                                void evaluate()
                                    throws Exception
                                {
                                    reseedTestCount.incrementAndGet();
                                }
                            };
                        }
                    };
                }
            });

        testDrbg.generate(new byte[20], null, false);
        check("selfTestCount should be 1", selfTestCount.get() == 1);
        check("reseedTestCount should be 0", reseedTestCount.get() == 0);

        testDrbg.generate(new byte[20], null, true);
        check("selfTestCount should be 1", selfTestCount.get() == 1);
        check("reseedTestCount should be 1", reseedTestCount.get() == 1);
        // isFirst will be false
        testDrbg.generate(new byte[20], null, false);
        check("selfTestCount should be 1", selfTestCount.get() == 1);
        check("reseedTestCount should be 2", reseedTestCount.get() == 2);
    }
    */
}
