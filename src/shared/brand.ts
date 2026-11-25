/** A value of `T` branded as `Kind` so distinct domain strings cannot be confused. */
export type Brand<T, Kind extends string> = T & { readonly __brand: Kind };
