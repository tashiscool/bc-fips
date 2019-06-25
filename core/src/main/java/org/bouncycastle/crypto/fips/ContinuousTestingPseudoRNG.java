package org.bouncycastle.crypto.fips;

class ContinuousTestingPseudoRNG
    implements DRBG
 {
     // see FIPS 140-2 section 4.9.2 - we choose n as 64.
     private static final int MIN_RESOLUTION = 8;

     private final DRBG drbg;

     private volatile byte[] block;
     private volatile byte[] nextBlock;
     private volatile byte[] initialAdditionalInput;

     ContinuousTestingPseudoRNG(DRBG drbg, byte[] primaryAdditionalInput)
     {
         this.drbg = drbg;
         this.block = new byte[0];
         this.nextBlock = new byte[0];
         this.initialAdditionalInput = primaryAdditionalInput;
     }

     public int getBlockSize()
     {
         return drbg.getBlockSize();
     }

     public int getSecurityStrength()
     {
         return drbg.getSecurityStrength();
     }

     public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
     {
         if (FipsStatus.isErrorStatus())
         {
             throw new FipsOperationError(FipsStatus.getStatusMessage());
         }

         synchronized (this)
         {
             int rv;

             if (block.length != output.length)
             {
                 if (block.length < output.length)
                 {
                     block = new byte[getTestBlockSize(output.length)];
                     nextBlock = new byte[getTestBlockSize(output.length)];

                     if (initialAdditionalInput != null)
                     {
                         rv = drbg.generate(block, initialAdditionalInput, predictionResistant);
                         initialAdditionalInput = null;
                     }
                     else
                     {
                         rv = drbg.generate(block, null, predictionResistant);
                     }

                     if (rv < 0)
                     {
                         FipsStatus.moveToErrorStatus("DRBG unable to initialise");
                     }
                 }
                 else if (block.length != MIN_RESOLUTION)
                 {
                     byte[] tmp = new byte[getTestBlockSize(output.length)];

                     System.arraycopy(block, block.length - tmp.length, tmp, 0, tmp.length);

                     block = tmp;
                     nextBlock = new byte[getTestBlockSize(output.length)];
                 }
             }

             rv = drbg.generate(nextBlock, additionalInput, predictionResistant);
             if (rv < 0)
             {
                 return rv;
             }

             // FSM_STATE:5.2, "CONTINUOUS DRBG TEST", "The module is performing Continuous DRBG self-test"
             // FSM_TRANS:5.5, "CONDITIONAL TEST", "CONTINUOUS DRBG TEST", "Invoke Continuous DRBG test"
             if (areEqual(block, nextBlock, 0))
             {
                 // FSM_TRANS:5.7, "CONTINUOUS DRBG TEST", "SOFT ERROR", "Continuous DRBG test failed"
                 FipsStatus.moveToErrorStatus("Duplicate block detected in DRBG output");
             }
             // FSM_TRANS:5.6, "CONTINUOUS DRBG TEST", "CONDITIONAL TEST", "Continuous DRBG test successful"

             // note we only return output bytes to output array when we are sure there is no issue.
             System.arraycopy(nextBlock, 0, output, 0, output.length);
             System.arraycopy(nextBlock, 0, block, 0, block.length);
         }

         if (FipsStatus.isErrorStatus())
         {
             throw new FipsOperationError(FipsStatus.getStatusMessage());
         }

         return output.length;
     }

     public void reseed(byte[] additionalInput)
     {
         FipsStatus.isReady();

         synchronized (this)
         {
             block = new byte[0];
             nextBlock = new byte[0];
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

     private boolean areEqual(byte[] a, byte[] b, int bOff)
     {
         if (bOff + a.length > b.length)
         {
             return false;
         }

         for (int i = 0; i != a.length; i++)
         {
             if (a[i] != b[bOff + i])
             {
                 return false;
             }
         }

         return true;
     }

     // see FIPS 140-2 section 4.9.2 - we choose n as 64.
     private static int getTestBlockSize(int output)
     {
          if (output < MIN_RESOLUTION)
          {
              return MIN_RESOLUTION;
          }

          return output;
     }
 }