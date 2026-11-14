module example.com/app

go 1.22

toolchain go1.22.3

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/text v0.3.0 // indirect
	// a comment line
	example.com/pseudo v0.0.0-20200101120000-abcdefabcdef
	gopkg.in/yaml.v3 v3.0.1
	github.com/old/lib v2.0.0+incompatible
)

require github.com/single/dep v1.2.3

replace (
	github.com/pkg/errors => ../errors
)

exclude github.com/bad/mod v1.0.0

retract (
	v1.0.0
)
