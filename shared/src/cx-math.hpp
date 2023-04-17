#pragma once
// From https://github.com/elbeno/constexpr/blob/master/src/include/cx_math.h

#include <exception>
#include <limits>
#include <type_traits>

namespace dory::cx {

namespace internal {
// test whether values are within machine epsilon, used for algorithm
// termination
template <typename T>
constexpr bool feq(T x, T y) {
  return ((x > y) ? (x - y) : (y - x)) <= std::numeric_limits<T>::epsilon() * 2;
}
}  // namespace internal

//----------------------------------------------------------------------------
// exp by Taylor series expansion
namespace internal {
template <typename T>
constexpr T exp(T x, T sum, T n, int i, T t) {
  return feq(sum, sum + t / n) ? sum : exp(x, sum + t / n, n * i, i + 1, t * x);
}
}  // namespace internal
template <typename FloatingPoint>
constexpr FloatingPoint exp(
    FloatingPoint x,
    typename std::enable_if<
        std::is_floating_point<FloatingPoint>::value>::type* = nullptr) {
  return true ? internal::exp(x, FloatingPoint{1}, FloatingPoint{1}, 2, x)
              : throw std::runtime_error("Exp runtime error");
}

template <typename Integral>
constexpr double exp(
    Integral x,
    typename std::enable_if<std::is_integral<Integral>::value>::type* =
        nullptr) {
  return internal::exp<double>(x, 1.0, 1.0, 2, x);
}

//----------------------------------------------------------------------------
// natural logarithm using
// https://en.wikipedia.org/wiki/Natural_logarithm#High_precision
// domain error occurs if x <= 0
namespace internal {
template <typename T>
constexpr T log_iter(T x, T y) {
  return y + T{2} * (x - cx::exp(y)) / (x + cx::exp(y));
}
template <typename T>
constexpr T log(T x, T y) {
  return feq(y, log_iter(x, y)) ? y : log(x, log_iter(x, y));
}
constexpr long double e() { return 2.71828182845904523536l; }
// For numerical stability, constrain the domain to be x > 0.25 && x < 1024
// - multiply/divide as necessary. To achieve the desired recursion depth
// constraint, we need to account for the max double. So we'll divide by
// e^5. If you want to compute a compile-time log of huge or tiny long
// doubles, YMMV.

// if x <= 1, we will multiply by e^5 repeatedly until x > 1
template <typename T>
constexpr T logGT(T x) {
  return x > T{0.25} ? log(x, T{0})
                     : logGT<T>(x * e() * e() * e() * e() * e()) - T{5};
}
// if x >= 2e10, we will divide by e^5 repeatedly until x < 2e10
template <typename T>
constexpr T logLT(T x) {
  return x < T{1024} ? log(x, T{0})
                     : logLT<T>(x / (e() * e() * e() * e() * e())) + T{5};
}
}  // namespace internal

template <typename FloatingPoint>
constexpr FloatingPoint log(
    FloatingPoint x,
    typename std::enable_if<
        std::is_floating_point<FloatingPoint>::value>::type* = nullptr) {
  return x < 0 ? throw std::runtime_error("Log domain error")
               : x >= FloatingPoint{1024} ? internal::logLT(x)
                                          : internal::logGT(x);
}
template <typename Integral>
constexpr double log(
    Integral x,
    typename std::enable_if<std::is_integral<Integral>::value>::type* =
        nullptr) {
  return log(static_cast<double>(x));
}

//----------------------------------------------------------------------------
// other logarithms
template <typename FloatingPoint>
constexpr FloatingPoint log10(
    FloatingPoint x,
    typename std::enable_if<
        std::is_floating_point<FloatingPoint>::value>::type* = nullptr) {
  return log(x) / log(FloatingPoint{10});
}
template <typename Integral>
constexpr double log10(
    Integral x,
    typename std::enable_if<std::is_integral<Integral>::value>::type* =
        nullptr) {
  return log10(static_cast<double>(x));
}

template <typename FloatingPoint>
constexpr FloatingPoint log2(
    FloatingPoint x,
    typename std::enable_if<
        std::is_floating_point<FloatingPoint>::value>::type* = nullptr) {
  return log(x) / log(FloatingPoint{2});
}
template <typename Integral>
constexpr double log2(
    Integral x,
    typename std::enable_if<std::is_integral<Integral>::value>::type* =
        nullptr) {
  return log2(static_cast<double>(x));
}

}  // namespace dory::cx
