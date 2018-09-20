# salsa20-cipher-conn


```
go test -run=^$ -bench S
goos: linux
goarch: amd64
pkg: github.com/jannson/salsa20conn
BenchmarkAES-4                50          27625718 ns/op         303.65 MB/s      251681 B/op          0 allocs/op
BenchmarkSalsa20-4           100          11791429 ns/op         711.42 MB/s      125904 B/op          0 allocs/op
PASS
ok      github.com/jannson/salsa20conn  6.400s
```
