# go-spring v1.1.0-rc4 filter

依赖 go get github.com/zundaren/go-spring-filter
```
1.cors使用

server := SpringGin.New(cfg)

server.AddPrefilter(cors.DefaultPreFilter())
server.AddPrefilter(cors.New(cors.Options{AllowedOrigins: []string{"*"}}))

2.secure使用

server.AddPrefilter(secure.PreFilter(secure.Options{
			FrameDeny:          true,
			ContentTypeNosniff: true,
			BrowserXssFilter:   true,
		//	SSLRedirect: true,
}))

```
