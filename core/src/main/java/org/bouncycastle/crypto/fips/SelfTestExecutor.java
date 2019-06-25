package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;

class SelfTestExecutor
{
    static <T> T validate(FipsAlgorithm algorithm, T engine, BasicKatTest<T> test)
    {
        try
        {
            if (!test.hasTestPassed(engine))
            {
                FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError("Self test failed", algorithm));
            }

            return engine;
        }
        catch (Exception e)
        {
            FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError("Exception on self test: " + e.getMessage(), algorithm));
        }

        return null; // we'll never get this far
    }

    static <T> T validate(FipsAlgorithm algorithm, T engine, VariantKatTest<T> test)
    {
        try
        {
            test.evaluate(engine);

            return engine;
        }
        catch (TestFailedException e)
        {
            FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError(e.getMessage(), algorithm));
        }
        catch (Exception e)
        {
            FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError("Exception on self test: " + e.getMessage(), algorithm));
        }

        return null; // we'll never get this far
    }

    static void validate(FipsAlgorithm algorithm, VariantInternalKatTest test)
    {
        try
        {
            if (!algorithm.equals(test.getAlgorithm()))
            {
                 throw new TestFailedException("Inconsistent algorithm tag for " + algorithm);
            }

            test.evaluate();
        }
        catch (TestFailedException e)
        {
            FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError(e.getMessage(), algorithm));
        }
        catch (Exception e)
        {
            FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError("Exception on self test: " + e.getMessage(), algorithm));
        }
    }

    static <T> T validate(FipsAlgorithm algorithm, T parameters, ConsistencyTest<T> test)
    {
        try
        {
            if (!test.hasTestPassed(parameters))
            {
                FipsStatus.moveToErrorStatus(new FipsConsistencyTestFailedError("Consistency test failed", algorithm));
            }

            return parameters;
        }
        catch (Exception e)
        {
            FipsStatus.moveToErrorStatus(new FipsConsistencyTestFailedError("Exception on consistency test: " + e.getMessage(), algorithm));
        }

        return null; // we'll never get this far
    }

    static class TestFailedException
        extends RuntimeException
    {

        public TestFailedException(String message)
        {
            super(message);
        }
    }

    //
    // unused - for validation testing purposes only
    //

    static <T> T fail(FipsAlgorithm algorithm, T engine, BasicKatTest<T> test)
    {
        FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError("Self test failed", algorithm));

        return null; // we'll never get this far
    }

    static <T> T fail(FipsAlgorithm algorithm, T engine, VariantKatTest<T> test)
    {
        FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError("Kat test failed", algorithm));

        return null; // we'll never get this far
    }

    static void fail(FipsAlgorithm algorithm, VariantInternalKatTest test)
    {
        FipsStatus.moveToErrorStatus(new FipsSelfTestFailedError("Internal kat test failed", algorithm));
    }

    static <T> T fail(FipsAlgorithm algorithm, T parameters, ConsistencyTest<T> test)
    {
        FipsStatus.moveToErrorStatus(new FipsConsistencyTestFailedError("Consistency test failed", algorithm));

        return null; // we'll never get this far
    }
}
