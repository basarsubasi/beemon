package main

import (
	"testing"
)

func TestInt8ToStr(t *testing.T) {
	arr := []int8{'t', 'e', 's', 't', 0, 'i', 'n', 'g'}
	result := int8ToStr(arr)
	if result != "test" {
		t.Errorf("expected 'test', got '%s'", result)
	}

	arr2 := []int8{'f', 'u', 'l', 'l'}
	result2 := int8ToStr(arr2)
	if result2 != "full" {
		t.Errorf("expected 'full', got '%s'", result2)
	}
}
