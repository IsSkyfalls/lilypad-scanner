package main

import (
	_ "embed"
	"io"
	"io/ioutil"
	"lilypad-scanner/addr"
	"lilypad-scanner/log"
	"net"
	"time"
)

type ScanResult struct {
	ip       addr.IP4
	response string
}

//go:embed c2sconnect
var c2s_connect []byte

func worker(id int, iter *addr.CIDR4RevIterator, result chan ScanResult) {
	for {
		next, ok := iter.Next()
		if !ok {
			return
		}
		ip := next.ToNative()
		conn, err := net.DialTimeout("tcp", ip.String()+":"+"25565", time.Second*10)
		if err != nil {
			log.Debug().Logf("[%d] connection failed: %s", id, err)
		}
		_, err = conn.Write(c2s_connect)
		if err != nil {
			log.Debug().Logf("[%d] failed to write %s: %s", id, ip, err)
		}
		limit := io.LimitReader(conn, 1024)
		read, err := ioutil.ReadAll(limit)
		if err != nil {
			log.Debug().Logf("[%d] failed to read from %s: %s", id, ip, err)
		}
		if len(read) > 0 {
			log.Debug().Logf("[%d] first 1024 bytes from %s: %s", id, ip, string(read))
		}
		o := ScanResult{
			ip:       next,
			response: string(read),
		}
		result <- o
	}
}