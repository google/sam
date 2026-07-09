// Sample file with intentional issues for the reviewer pool to find.
package rates

import "sync"

var cache = map[string]float64{}
var mu sync.Mutex

func Set(k string, v float64) {
	mu.Lock()
	cache[k] = v
	mu.Unlock()
}

func Get(k string) float64 {
	return cache[k]
}
