package main

import (
	"fmt"
	"lilypad-scanner/addr"
	"lilypad-scanner/log"
	"strings"
	"sync"
	"time"
)

func main() {
	cidr := addr.NewCIDR4Reversed("0.0.0.205|8")
	iter := cidr.Iterator().
		RegisterSkip(addr.NewCIDR4("0.0.0.0/8")).
		RegisterSkip(addr.NewCIDR4("10.0.0.0/8")).
		RegisterSkip(addr.NewCIDR4("100.64.0.0/10")).
		RegisterSkip(addr.NewCIDR4("127.0.0.0/8")).
		RegisterSkip(addr.NewCIDR4("169.254.0.0/16")).
		RegisterSkip(addr.NewCIDR4("172.16.0.0/12")).
		RegisterSkip(addr.NewCIDR4("192.0.0.0/24")).
		RegisterSkip(addr.NewCIDR4("192.0.2.0/24")).
		RegisterSkip(addr.NewCIDR4("192.88.99.0/24")).
		RegisterSkip(addr.NewCIDR4("192.168.0.0/16")).
		RegisterSkip(addr.NewCIDR4("198.18.0.0/15")).
		RegisterSkip(addr.NewCIDR4("224.0.0.0/4")).
		RegisterSkip(addr.NewCIDR4("240.0.0.0/4"))

	results := make(chan ScanResult, 10)
	responded := 0
	matched := 0
	go resultConsumer(results, &responded, &matched)
	go mainOutput(iter, &responded, &matched)

	block := make(chan bool)
	wg := sync.WaitGroup{}
	for i := 0; i < 1000; i++ {
		go func(id int) {
			wg.Add(1)
			<-block
			worker(id, iter, results)
			wg.Done()
		}(i)
	}
	close(block)
	wg.Wait()
}

func resultConsumer(c chan ScanResult, responded *int, matched *int) {
	for {
		result := <-c
		*responded++
		log.Info().Logf("Server %s responded with: %s", result.ip, result.response)

		if strings.Contains(result.response, "client") {
			log.Info().Log("THIS MIGHT BE A MATCH")
			*matched++
		}
	}
}

func mainOutput(iter *addr.CIDR4RevIterator, responded *int, matched *int) {
	tick := time.NewTicker(time.Second * 2)
	t := time.Now()
	for {
		clear()
		fmt.Println("Skyfalls' Low Performance Single-threaded Lilypad Scanner")
		fmt.Printf("Total ips: %d\n", iter.CountTotal())
		fmt.Printf("Current: %d - %s\n", iter.Counter(), iter.Current())
		progress := float64(iter.Counter()) / float64(iter.CountTotal())
		elapsed := time.Now().Sub(t)
		fmt.Printf("Progress: %.2f%% | ETA: %s", progress*100, time.Duration(elapsed.Seconds()/progress))
		fmt.Printf("Time Elapsed: %s", elapsed)
		_ = <-tick.C
	}
}

func clear() {
	fmt.Print("\033[H\033[2J")
}
