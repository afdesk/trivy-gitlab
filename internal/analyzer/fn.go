package analyzer

func valueOrDefault(val, def string) string {
	if val == "" {
		return def
	}

	return val
}

func mapf[T, U any](data []T, f func(T) U) []U {

	res := make([]U, 0, len(data))
	for _, e := range data {
		res = append(res, f(e))
	}
	return res
}

func filterf[T any](data []T, f func(T) bool) []T {

	fltd := make([]T, 0, len(data))

	for _, e := range data {
		if f(e) {
			fltd = append(fltd, e)
		}
	}
	return fltd
}
