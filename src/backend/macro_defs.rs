//! Defines macros that implement arithmetic operations for both backends. Since
//! those backends already implement all arithmetic with minimal differences,
//! all those macros amount to passing the operations down to the underlying
//! implementation

/// Make arithmetic operations between the number and a primitive, like `impl
/// Add<i32> for Integer`. Rug instatiation will pass in `complete`, num-bigint
/// will pass nothing
macro_rules! make_ops_for_primitive {
    ($type:ident, $class:ident, $method:ident, $prim:ty $(,)? $(, $complete:ident)?) => {
        impl std::ops:: $class <$prim> for $type {
            type Output = $type;
            fn $method(self, rhs: $prim) -> $type {
                $type(self.0.$method(rhs))
            }
        }
        impl std::ops:: $class <$prim> for &$type {
            type Output = $type;
            fn $method(self, rhs: $prim) -> $type {
                $type(
                    (&self.0).$method(rhs)
                        $( .$complete() )?
                )
            }
        }
    };
}
/// Make arithmetic operations between a primitive and the number, like `impl
/// Add<&Integer> for i32`. This is like the macro above, but with arguments
/// flipped. Rug instatiation will pass in `complete`, num-bigint will pass
/// nothing
macro_rules! make_rev_ops_for_primitive {
    ($type:ident, $class:ident, $method:ident, $prim:ty, $($complete:ident)?) => {
        impl std::ops:: $class <$type> for $prim {
            type Output = $type;
            fn $method(self, rhs: $type) -> $type {
                $type(
                    self.$method(&rhs.0)
                        $( .$complete() )?
                )
            }
        }
        impl std::ops:: $class <&$type> for $prim {
            type Output = $type;
            fn $method(self, rhs: &$type) -> $type {
                $type(
                    self.$method(&rhs.0)
                        $( .$complete() )?
                )
            }
        }
    };
}

/// Make arithemtic assignment operations between the number and a primitive,
/// like `impl AddAssign<i32> for Integer`. Num-bigint will pass in
/// `BigInt::from` for bitwise arithmetic operations, rug will pass nothing
macro_rules! make_assign_for_primitive {
    ($type:ident, $class:ident, $method:ident, $prim:ty $(,)? $(, $from:expr)?) => {
        impl std::ops:: $class <$prim> for $type {
            fn $method(&mut self, rhs: $prim) {
                $( let rhs = $from(rhs); )?
                self.0.$method(rhs)
            }
        }
    };
}

/// Make one arithmetic operation between Integer, itself, and all primitives.
/// Rug instatiation will pass in `complete`, num-bigint will pass nothing
macro_rules! make_ops {
    ($type:ident, $class:ident, $method:ident $(, $complete:ident)?) => {
        // All options with self
        impl std::ops:: $class <$type> for $type {
            type Output = $type;
            fn $method(self, rhs: $type) -> $type {
                $type(self.0.$method(rhs.0))
            }
        }
        impl std::ops:: $class <$type> for &$type {
            type Output = $type;
            fn $method(self, rhs: $type) -> $type {
                $type((&self.0).$method(rhs.0))
            }
        }
        impl std::ops:: $class <&$type> for $type {
            type Output = $type;
            fn $method(self, rhs: &$type) -> $type {
                $type(self.0.$method(&rhs.0))
            }
        }
        impl std::ops:: $class <&$type> for &$type {
            type Output = $type;
            fn $method(self, rhs: &$type) -> $type {
                $type(
                    (&self.0).$method(&rhs.0)
                        $( .$complete() )?
                )
            }
        }

        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, i8, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, i8, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, u8, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, u8, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, i16, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, i16, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, u16, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, u16, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, i32, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, i32, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, u32, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, u32, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, i64, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, i64, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, u64, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, u64, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, isize, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, isize, $($complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!($type, $class, $method, usize, $($complete)?);
        $crate::backend::macro_defs::make_rev_ops_for_primitive!($type, $class, $method, usize, $($complete)?);
    };
}

/// Make one arithmetic assignment operation between Integer, itself, and all
/// primitives
macro_rules! make_assign {
    ($type:ident, $class:ident, $method:ident) => {
        impl std::ops::$class<$type> for $type {
            fn $method(&mut self, rhs: $type) {
                self.0.$method(rhs.0)
            }
        }
        impl std::ops::$class<&$type> for $type {
            fn $method(&mut self, rhs: &$type) {
                self.0.$method(&rhs.0)
            }
        }
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, i8);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, u8);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, i16);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, u16);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, i32);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, u32);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, i64);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, u64);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, isize);
        $crate::backend::macro_defs::make_assign_for_primitive!($type, $class, $method, usize);
    };
}

/// Implement all arithmetic operations for this big number type. Rug
/// instatiation will pass in `complete`, num-bigint will pass nothing
macro_rules! make_all_ops {
    ($type:ident $(, $complete:ident)?) => {
        $crate::backend::macro_defs::make_ops!(Integer, Add, add $(, $complete)?);
        $crate::backend::macro_defs::make_ops!(Integer, Sub, sub $(, $complete)?);
        $crate::backend::macro_defs::make_ops!(Integer, Mul, mul $(, $complete)?);
        $crate::backend::macro_defs::make_ops!(Integer, Div, div $(, $complete)?);
        $crate::backend::macro_defs::make_ops!(Integer, Rem, rem $(, $complete)?);
        $crate::backend::macro_defs::make_assign!(Integer, AddAssign, add_assign);
        $crate::backend::macro_defs::make_assign!(Integer, SubAssign, sub_assign);
        $crate::backend::macro_defs::make_assign!(Integer, MulAssign, mul_assign);
        $crate::backend::macro_defs::make_assign!(Integer, DivAssign, div_assign);
        $crate::backend::macro_defs::make_assign!(Integer, RemAssign, rem_assign);

        $crate::backend::macro_defs::make_ops_for_primitive!(Integer, Shl, shl, u32 $(, $complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!(Integer, Shl, shl, i32 $(, $complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!(Integer, Shl, shl, usize $(, $complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!(Integer, Shr, shr, u32 $(, $complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!(Integer, Shr, shr, i32 $(, $complete)?);
        $crate::backend::macro_defs::make_ops_for_primitive!(Integer, Shr, shr, usize $(, $complete)?);

        impl std::ops::Neg for $type {
            type Output = $type;
            fn neg(self) -> Self::Output {
                $type(self.0.neg())
            }
        }
        impl std::ops::Neg for & $type {
            type Output = $type;
            fn neg(self) -> Self::Output {
                let r = (-&self.0)
                    $(. $complete())?
                    ;
                $type(r)
            }
        }

        impl From<u16> for $type {
            fn from(value: u16) -> Self {
                $type(value.into())
            }
        }
        impl From<u32> for $type {
            fn from(value: u32) -> Self {
                $type(value.into())
            }
        }
        impl From<i32> for $type {
            fn from(value: i32) -> Self {
                $type(value.into())
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    }
}

/// Make one bitwise assignment operation between Integer, itself, and all
/// primitives. Num-bigint will pass in `BigInt::from`, rug will pass nothing
macro_rules! make_all_bitops {
    ($type:ident $(, $from:expr)?) => {
        $crate::backend::macro_defs::make_assign_for_primitive!(Integer, ShlAssign, shl_assign, u32);
        $crate::backend::macro_defs::make_assign_for_primitive!(Integer, ShrAssign, shr_assign, u32);
        $crate::backend::macro_defs::make_assign_for_primitive!(Integer, BitOrAssign, bitor_assign, u32 $(, $from)?);
        $crate::backend::macro_defs::make_assign_for_primitive!(Integer, BitAndAssign, bitand_assign, u32 $(, $from)?);
    }
}

#[doc(hidden)]
pub(crate) use make_assign;
#[doc(hidden)]
pub(crate) use make_assign_for_primitive;
#[doc(hidden)]
pub(crate) use make_ops;
#[doc(hidden)]
pub(crate) use make_ops_for_primitive;
#[doc(hidden)]
pub(crate) use make_rev_ops_for_primitive;

pub(crate) use make_all_bitops;
pub(crate) use make_all_ops;
