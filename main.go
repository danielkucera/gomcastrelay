package main

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	maxDatagramSize = 1600
	listen_string   = ":8080"
)

func main() {
	router := gin.Default()

	allowedIPsEnv := os.Getenv("ALLOWED_IPS")
	allowedIPs := strings.Split(allowedIPsEnv, ",")

	router.GET("/:address", func(c *gin.Context) {
		address := c.Param("address")

		client := c.ClientIP()
		log.Printf("client %s requesting %s\n", client, address)

		if len(allowedIPsEnv) > 0 {
			allowed := false
			for _, ip := range allowedIPs {
				if strings.HasPrefix(client, ip) {
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
			return
		}
		log.Printf("listening on %s\n", addr)
		l, err := net.ListenPacket("udp", addr.String())
		if err != nil {
			c.String(503, err.Error())
			return
		}
		defer l.Close()

		pc := ipv4.NewPacketConn(l)

		err = pc.JoinGroup(nil, addr)
		if err != nil {
			log.Printf("join: join error: %v", err)
			c.String(503, err.Error())
			return
		}

		err = pc.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true)
		if err != nil {
			log.Printf("join: control message flags error: %v", err)
		}

		b := make([]byte, maxDatagramSize)

		httpc, rw, err := c.Writer.Hijack()
		defer httpc.Close()

		rw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

		lastSrc := ""
		lastPacket := time.Now()
		closed := false
		go func() {
			go rw.Read(make([]byte, 1))
			<-c.Writer.CloseNotify()
			log.Printf("client closed connection")
			closed = true
		}()

		for !closed {
			err = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			if err != nil {
				log.Printf("set read dealine error: %v", err)
			}

			n, cm, src, err := pc.ReadFrom(b)
			if err != nil {
				log.Printf("stream reader failed %v\n", err)
				if strings.Contains(err.Error(), "timeout") { //invalidate last valid src and accept any
					lastSrc = ""
					continue
				} else {
					return
				}
			}
			if addr.IP.String() != cm.Dst.String() {
				// We have to filter dst address here because Golang tries to be too smart
				// https://github.com/golang/go/issues/34728
				continue
			}

			if lastSrc == "" || lastPacket.Add(3*time.Second).Before(time.Now()) {
				log.Printf("locked to source %v\n", src)
				lastSrc = src.String()
			} else {
				if src.String() != lastSrc {
					//log.Printf("source mismatch %v %v\n", src, lastSrc)
					continue
				}
			}
			lastPacket = time.Now()

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
