module github.com/local/tvtunx

go 1.24.7

require (
	github.com/quic-go/quic-go v0.48.2
	golang.org/x/crypto v0.26.0
)

require (
	github.com/quic-go/qpack v0.5.1 // indirect
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
)

replace golang.org/x/crypto => github.com/golang/crypto v0.26.0

replace golang.org/x/sys => github.com/golang/sys v0.23.0

replace golang.org/x/net => github.com/golang/net v0.28.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20240808152545-0cdaa3abc0fa

replace golang.org/x/text => github.com/golang/text v0.17.0

replace golang.org/x/sync => github.com/golang/sync v0.8.0

replace golang.org/x/tools => github.com/golang/tools v0.24.0

replace golang.org/x/mod => github.com/golang/mod v0.20.0

replace go.uber.org/mock => github.com/uber-go/mock v0.4.0
