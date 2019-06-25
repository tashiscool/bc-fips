/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.math.field;

public interface Polynomial
{
    int getDegree();

//    BigInteger[] getCoefficients();

    int[] getExponentsPresent();

//    Term[] getNonZeroTerms();
}
