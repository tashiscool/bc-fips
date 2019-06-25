/**
 * Low-level API for performing calculations on elliptic curves, in particular point addition, point doubling,
 * and efficient scalar multiplication.
 *
 * The main API is quite general, with support for arbitrary curves over both prime (large-characteristic) and binary
 * fields (but only short Weierstrass form is currently supported). Custom implementations of many commonly-used
 * curves are available in sub-packages of org.bouncycastle.math.ec.custom, and are typically much faster.
 */
package org.bouncycastle.math.ec;

