package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"net"
)

const (
	maxDatagramSize = 1600
	listen_string   = ":8080"
)

func main() {
	router := gin.Default()

	allowedIPs := [...]string{
		"127.0.0.1",
		"95.85.254.39",
		"46.227.180.235",
	}

	router.GET("/:address", func(c *gin.Context) {
		address := c.Param("address")

		client := c.ClientIP()
		log.Printf("client %s requesting %s\n", client, address)

		if len(allowedIPs) > 0 {
			allowed := false
			for _, ip := range allowedIPs {
				if client == ip {
					allowed = true
				}
			}
			if !allowed {
				c.String(403, "Forbiden source IP")
				return
			}
		}

		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			c.String(503, err.Error())
		}
		log.Printf("listening on %s\n", addr)
		l, err := net.ListenMulticastUDP("udp", nil, addr)

		defer l.Close()

		l.SetReadBuffer(2 * 1024 * 1024)
		b := make([]byte, maxDatagramSize)

		_, rw, err := c.Writer.Hijack()

		rw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

		var lastSrc *net.UDPAddr
		for {
			n, src, err := l.ReadFromUDP(b)
			if err != nil {
				log.Printf("stream reader failed %s\n", err)
				return
			}

			if lastSrc == nil {
				log.Printf("locked to source %v\n", src)
				lastSrc = src
			} else {
				if !src.IP.Equal(lastSrc.IP) {
					//log.Printf("source mismatch %v %v\n", src, lastSrc)
					continue
				}
			}

			data := b[:n]
			//log.Printf("packet %v %d %d\n", src, n, len(data))

			if len(data)%188 == 12 { //we probably have RTP stream
				data = data[12:]
			}

			_, err = rw.Write(data)
			if err != nil {
				log.Printf("stream writer failed %s\n", err)
				return
			}
		}
	})

	log.Printf("Starting on port %s", listen_string)
	router.Run(listen_string)
}
