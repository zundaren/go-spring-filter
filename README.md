1.go-spring v1.1.0-rc4 cors

```
go get github.com/zundaren/go-spring-filter

server := SpringGin.New(cfg)

server.AddPrefilter(cors.DefaultPreFilter())
server.AddPrefilter(cors.New(cors.Options{AllowedOrigins: []string{"*"}}))

```

