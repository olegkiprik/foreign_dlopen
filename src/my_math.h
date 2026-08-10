#if !defined(MY_MATH_H)
#define MY_MATH_H

#if defined(FOREIGN_DLOPEN_STATIC)
#define MY_VISIBILITY static
#else
#define MY_VISIBILITY extern
#endif

MY_VISIBILITY double (*my_fabs)(double);
MY_VISIBILITY double (*my_fmod)(double);
MY_VISIBILITY double (*my_exp)(double);
MY_VISIBILITY double (*my_log)(double);
MY_VISIBILITY double (*my_log10)(double);
MY_VISIBILITY double (*my_pow)(double, double);
MY_VISIBILITY double (*my_sqrt)(double);
MY_VISIBILITY double (*my_sin)(double);
MY_VISIBILITY double (*my_cos)(double);
MY_VISIBILITY double (*my_tan)(double);
MY_VISIBILITY double (*my_asin)(double);
MY_VISIBILITY double (*my_acos)(double);
MY_VISIBILITY double (*my_atan)(double);
MY_VISIBILITY double (*my_atan2)(double, double);
MY_VISIBILITY double (*my_sinh)(double);
MY_VISIBILITY double (*my_cosh)(double);
MY_VISIBILITY double (*my_tanh)(double);
MY_VISIBILITY double (*my_ceil)(double);
MY_VISIBILITY double (*my_floor)(double);
MY_VISIBILITY double (*my_frexp)(double);
MY_VISIBILITY double (*my_ldexp)(double);
MY_VISIBILITY double (*my_modf)(double);

static double fabs(double x)
{
	return (*my_fabs)(x);
}

static double fmod(double x)
{
	return (*my_fmod)(x);
}

static double exp(double x)
{
	return (*my_exp)(x);
}

static double log(double x)
{
	return (*my_log)(x);
}

static double log10(double x)
{
	return (*my_log10)(x);
}

static double pow(double x, double y)
{
	return (*my_pow)(x, y);
}

static double sqrt(double x)
{
	return (*my_sqrt)(x);
}

static double sin(double x)
{
	return (*my_sin)(x);
}

static double cos(double x)
{
	return (*my_cos)(x);
}

static double tan(double x)
{
	return (*my_tan)(x);
}

static double asin(double x)
{
	return (*my_asin)(x);
}

static double acos(double x)
{
	return (*my_acos)(x);
}

static double atan(double x)
{
	return (*my_atan)(x);
}

static double atan2(double x, double y)
{
	return (*my_atan2)(x, y);
}

static double sinh(double x)
{
	return (*my_sinh)(x);
}

static double cosh(double x)
{
	return (*my_cosh)(x);
}

static double tanh(double x)
{
	return (*my_tanh)(x);
}

static double ceil(double x)
{
	return (*my_ceil)(x);
}

static double floor(double x)
{
	return (*my_floor)(x);
}

static double frexp(double x)
{
	return (*my_frexp)(x);
}

static double ldexp(double x)
{
	return (*my_ldexp)(x);
}

static double modf(double x)
{
	return (*my_modf)(x);
}

#endif /* MY_MATH_H */
