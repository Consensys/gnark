/*
Package emulated implements operations over any modulus.

# Non-native computation in circuit

Usually, the computations in a SNARK circuit are performed in the 'native' field
of the curve. The native field is defined by the scalar field of the underlying
curve. This package implements non-native arithmetic on top of the native field
to emulate operations in any field and ring.

This package does this by splitting the element into smaller limbs. The
parameters for splitting the limb and defining the modulus are stored in types
implementing [FieldParams] type. The elements are parametrized by those types to
make compile-time distinction between different emulated fields.

This package defines [Element] type which stores the element value in split
limbs. On top of the Element instance, this package defines typical arithmetic
as addition, multiplication and subtraction. If the modulus is a prime (i.e.
defines a finite field), then inversion and division operations are also
possible.

The results of the operations are not always reduced to be less than the
modulus. For consecutive operations it is necessary to manually reduce the value
using [Field.Reduce] method. The number of operations which can be performed
without reduction depends when the operations result starts overflowing the
limbs.

# Element representation

We operate in the scalar field of the SNARK curve (native field). Denote the
modulus of the native field as 'q'. Representing the modulus of the native field
requires 'n' bits. We wish to emulate operations over modulus 'r'. Modulus r may
or may not be a prime. If r is not prime, then we do not have inversion and
division operations (the corresponding methods panic). Let the bitlength of r be
'm'. We note that r may be smaller, larger or equal to q.

To represent an element x ∈ N_r, we choose the limb width 'w' such that

	w ≤ (m-1)/2

and write its integer representation as

	x = ∑_{i=0}^k x_i 2^{w i}.

Here, the variable 'x_i' is the w bits of x starting from 2^{w i}, 'k' is the
number of limbs and is computed as

	k = (n+w-1)/w,   // NB! integer division

and 'i' is the limb index. In this representation the element is represented in
little-endian (least significant limbs first) order. We do not necessarily
require that the limb values x_i are less than 2^w. This may happen if the limb
values are obtained as a result of arithmetic operations between elements. If we
know that the limb values do not overflow 2^w, then we say that the element is
in normal form.

In the implementation, we have two functions for splitting an element into limbs
and composing an element from limbs -- [decompose] and [recompose]. The
[recompose] function also accepts element in non-normal form.

# Elements in non-normal form

When an element is initialized, the limbs are in normal form, i.e. the values of
the limbs have bitwidth strictly less than w. As addition and multiplication are
performed on limbs natively, then the bitwidths of the limbs of the result may
be larger than w. We track the number of bits which may exceed the initial width
of the limbs. We denote the number of such excess bits as 'f' and call it
overflow. The total maximal bitwidth of the limbs is then

	w+f.

Keep in mind that parameter w is global for all emulated elements and f is
individual for every individual element.

To compute the overflow for the operations, we consider the arithmetic
operations which affect the overflow. In this implementation only addition is
done natively (limb-wise addition). When adding two elements, the bitwidth of
the result is up to one bit wider than the width of the widest element.

In the context of overflows, if the overflows of the addends are f_0 and f_1
then the overflow value f' for the sum is computed as

	f' = max(f_0, f_1)+1.

# Multiplication

The complexity of native limb-wise multiplication is k^2. This translates
directly to the complexity in the number of constraints in the constraint
system. However, alternatively, when instead computing the limb values
off-circuit and constructing a system of k linear equations, we can ensure that
the product was computed correctly.

Let the factors be

	x = ∑_{i=0}^k x_i 2^{w i}

and

	y = ∑_{i=0}^k y_i 2^{w i}.

For computing the product, we compute off-circuit the limbs

	z_i = ∑_{j, j'>0, j+j'=i, j+j'≤2k-2} x_{j} y_{j'}, // in MultiplicationHint()

and assert in-circuit

	∑_{i=0}^{2k-2} z_i c^i = (∑_{i=0}^k x_i) (∑_{i=0}^k y_i), ∀ c ∈ {1, ..., 2k-1}.

Computing the overflow for the multiplication result is slightly more
complicated. The overflow for

	x_{j} y_{j'}

is

	w+f+f'+1.

Naively, as the limbs of the result are summed over all 0 ≤ i ≤ 2k-2, then the
overflow of the limbs should be

	w+f+f'+2k-1.

For computing the number of bits and thus in the overflow, we can instead look
at the maximal possible value. This can be computed by

	(2^{2w+f+f'+2}-1)*(2k-1).

Its bitlength is

	2w+f+f'+1+log_2(2k-1),

which leads to maximal overflow of

	w+f+f'+1+log_2(2k-1).

# Subtraction

We perform subtraction limb-wise between the elements x and y. However, we have
to ensure than any limb in the result does not result in overflow, i.e.

	x_i ≥ y_i, ∀ 0≤i<k.

As this does not hold in general, then we need to pad x such that every limb x_i
is strictly larger than y_i.

The additional padding 'u' has to be divisible by the emulated modulus r and
every limb u_i must be larger than x_i-y_i. Let f' be the overflow of y. We
first compute the limbs u'_i as

	u'_i = 1 << (w+f'), ∀ 0≤i<k.

Now, as u' is not divisible by r, we need to compensate for it:

	u'' = u' + regroup(r - (u' % r)),

where regroup() regroups the argument so that it is in normal form (i.e. first
applies recompose() and then decompose() method).

We see that u” is now such that it is divisible by r and its every limb is
larger than every limb of b. The subtraction is performed as

	z_i = x_i + u''_i - y_i, ∀ 0≤i<k.

# Equality checking

The package provides two ways to check equality -- limb-wise equality check and
checking equality by value.

In the limb-wise equality check we check that the integer values of the elements
x and y are equal. We have to carry the excess using bit decomposition (which
makes the computation fairly inefficient). To reduce the number of bit
decompositions, we instead carry over the excess of the difference of the limbs
instead. As we take the difference, then similarly as computing the padding in
subtraction algorithm, we need to add padding to the limbs before subtracting
limb-wise to avoid underflows. However, the padding in this case is slightly
different -- we do not need the padding to be divisible by the modulus, but
instead need that the limb padding is larger than the limb which is being
subtracted.

Lets look at the algorithm itself. We assume that the overflow f of x is larger
than y. If overflow of y is larger, then we can just swap the arguments and
apply the same argumentation. Let

	maxValue = 1 << (k+f), // padding for limbs
	maxValueShift = 1 << f.  // carry part of the padding

For every limb we compute the difference as

	diff_0 = maxValue+x_0-y_0,
	diff_i = maxValue+carry_i+x_i-y_i-maxValueShift.

We check that the normal part of the difference is zero and carry the rest over
to next limb:

	diff_i[0:k] == 0,
	carry_{i+1} = diff_i[k:k+f+1] // we also carry over the padding bit.

Finally, after we have compared all the limbs, we still need to check that the
final carry corresponds to the padding. We add final check:

	carry_k == maxValueShift.

We can further optimise the limb-wise equality check by first regrouping the
limbs. The idea is to group several limbs so that the result would still fit
into the scalar field. If

	x = ∑_{i=0}^k x_i 2^{w i},

then we can instead take w' divisible by w such that

	x = ∑_{i=0}^(k/(w'/w)) x'_i 2^{w' i},

where

	x'_j = ∑_{i=0}^(w'/w) x_{j*w'/w+i} 2^{w i}.

For element value equality check, we check that two elements x and y are equal
modulo r and for that we need to show that r divides x-y. As mentioned in the
subtraction section, we add sufficient padding such that x-y does not underflow
and its integer value is always larger than 0. We use hint function to compute z
such that

	x-y = z*r,

compute z*r and use limbwise equality checking to show that

	x-y == z*r.

# Bitwidth enforcement

When element is computed using hints, we need to ensure that every limb is not
wider than k bits. For that, we perform bitwise decomposition of every limb and
check that k lower bits are equal to the whole limb. We omit the bitwidth
enforcement for multiplication as the correctness of the limbs is ensured using
the corresponding system of linear equations.

Additionally, we apply bitwidth enforcement for elements initialized from
integers.

# Modular reduction

To reduce the integer value of element x to be less than the modulus, we compute
the remainder x' of x modulo r using hint, enforce the bitwidth of x' and assert
that

	x' == x

using element equality checking.

# Values computed using hints

We additionally define functions for computing inverse of an element and ratio
of two elements. Both function compute the actual value using hint and then
assert the correctness of the operation using multiplication.

# Constant values

The package currently does not explicitly differentiate between constant and
variable elements. The builder may track some elements as being constants. Some
operations have a fast track path for cases when all inputs are constants. There
is [Field.MulConst], which provides variable by constant multiplication.
*/
package emulated
