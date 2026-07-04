package main

// int8ToStr converts a null-terminated int8 slice (often coming from eBPF C char arrays) into a Go string.
func int8ToStr(arr []int8) string {
	var b []byte
	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
