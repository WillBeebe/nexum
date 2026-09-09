# Using Nexum from Go

Nexum v0.2.0 is one Go module under Apache-2.0. Its client package is `nex`:

```go
import "github.com/WillBeebe/nexum/nex"
```

Requires Go 1.25 or newer. No Comlink server, GPU, model account or private
implementation checkout is required. The repository and Go module are public;
normal Go proxy and checksum verification apply.

## Add the library

Inside your own Go module:

```sh
go get github.com/WillBeebe/nexum/nex@v0.2.0
```

Commit your application's go.mod and go.sum. Keep the version pinned for
reproducible builds. Nexum and nex do not require separate library downloads.

## Install the command

```sh
go install github.com/WillBeebe/nexum/cmd/nex@v0.2.0
nex demo
```

Ensure GOBIN (or the default GOPATH/bin) is on PATH. The current command runs a
local agreement demonstration; it is not a remote daemon or production service
manager. Applications use the Go API for integrations.

## Local development override

For a local clean Nexum checkout, use a temporary application replacement:

```sh
go mod edit -replace=github.com/WillBeebe/nexum=/absolute/path/to/nexum
go mod tidy
```

Remove it before releasing your application. A version-suffixed `go install`
resolves the tagged module and does not use local replacements. To install a
local command build, run `go install ./cmd/nex` from the Nexum checkout.

Git tags are the Go release mechanism; prebuilt binaries and a GitHub Release
page are optional conveniences. See [Go's publishing guide](https://go.dev/doc/modules/publishing)
and [the module/install reference](https://go.dev/ref/mod#go-install).
