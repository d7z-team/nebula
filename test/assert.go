package test

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// AssertDeepCopyEqual checks value equality and independent mutable storage.
// time.Time and netip.Addr may share immutable location and zone data.
func AssertDeepCopyEqual(t *testing.T, a, b any) {
	t.Helper()
	if !assert.Equal(t, a, b) {
		return
	}

	var check func(x, y reflect.Value, field string)
	check = func(x, y reflect.Value, field string) {
		t.Helper()
		if !x.IsValid() || x.Type() == reflect.TypeFor[time.Time]() || x.Type() == reflect.TypeFor[netip.Addr]() {
			return
		}
		switch x.Kind() {
		case reflect.Interface:
			check(x.Elem(), y.Elem(), field)
		case reflect.Pointer:
			if x.Type() == reflect.TypeFor[*time.Location]() && x.Pointer() == reflect.ValueOf(time.Local).Pointer() && x.Pointer() == y.Pointer() {
				return
			}
			if !x.IsNil() && assert.NotEqual(t, x.Pointer(), y.Pointer(), "%s shares a pointer", field) {
				check(x.Elem(), y.Elem(), field)
			}
		case reflect.Map:
			if x.IsNil() || !assert.NotEqual(t, x.Pointer(), y.Pointer(), "%s shares a map", field) {
				return
			}
			for _, k := range x.MapKeys() {
				check(x.MapIndex(k), y.MapIndex(k), fmt.Sprintf("%s[%v]", field, k))
			}
		case reflect.Slice:
			// Capacity matters even for empty slices: appending can overwrite the other copy.
			size := x.Type().Elem().Size()
			if size > 0 && x.Cap() > 0 && y.Cap() > 0 {
				left, right := x.Pointer(), y.Pointer()
				overlap := left <= right && right-left < uintptr(x.Cap())*size || right < left && left-right < uintptr(y.Cap())*size
				if !assert.False(t, overlap, "%s shares slice storage", field) {
					return
				}
			}
			fallthrough
		case reflect.Array:
			for i := 0; i < x.Len(); i++ {
				check(x.Index(i), y.Index(i), fmt.Sprintf("%s[%d]", field, i))
			}
		case reflect.Struct:
			for i := 0; i < x.NumField(); i++ {
				check(x.Field(i), y.Field(i), field+"."+x.Type().Field(i).Name)
			}
		}
	}
	check(reflect.ValueOf(a), reflect.ValueOf(b), fmt.Sprintf("%T", a))
}
