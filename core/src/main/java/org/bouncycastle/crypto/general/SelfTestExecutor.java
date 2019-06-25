package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;

class SelfTestExecutor
{
    static <T> T validate(Algorithm algorithm, T engine, BasicKatTest<T> test)
    {
        try
        {
            if (!test.hasTestPassed(engine))
            {
                throw new OperationError("Self test failed: " + algorithm.getName());
            }

            return engine;
        }
        catch (Exception e)
        {
            throw new OperationError("Exception on self test: " + algorithm.getName(), e);
        }
    }

    static <T> T validate(Algorithm algorithm, T parameters, ConsistencyTest<T> test)
    {
        try
        {
            if (!test.hasTestPassed(parameters))
            {
                throw new OperationError("Consistency test failed: " + algorithm.getName());
            }

            return parameters;
        }
        catch (Exception e)
        {
            throw new OperationError("Consistency test exception: " + algorithm.getName(), e);
        }
    }

    static <T> T validate(Algorithm algorithm, T engine, VariantKatTest<T> test)
    {
        try
        {
            test.evaluate(engine);

            return engine;
        }
        catch (TestFailedException e)
        {
            throw new OperationError(e.getMessage() + ": " + algorithm.getName());
        }
        catch (Exception e)
        {
            throw new OperationError("Exception on self test: " + algorithm.getName(), e);
        }
    }

    static class TestFailedException
        extends RuntimeException
    {

        public TestFailedException(String message)
        {
            super(message);
        }
    }
}
