package main

import (
	"flag"
	"fmt"
	"lilypad-scanner/addr"
	"lilypad-scanner/log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	cidrStr := flag.String("cidr", "0.0.0.205|8", "specify the cidr range, only reversed format is supported(0.0.0.255|8)")
	resume := flag.Uint("resume", 0, "resume pointer, last current value minus total worker count")
	workers := flag.Int("workers", 8000, "worker count")
	verbose := flag.Bool("verbose", false, "chatty mode")

	flag.Parse()

	fmt.Printf("Launched with cidr_rev: %s, resume: %d. workers: %d, verbose: %t\n", *cidrStr, *resume, *workers, *verbose)

	cidr := addr.NewCIDR4Reversed(*cidrStr)
	iter := cidr.Iterator().Resume(uint32(*resume)).
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

	runtime.GOMAXPROCS(runtime.NumCPU() - 1)

	results := make(chan ScanResult, 10)
	responded := 0
	matched := 0
	go resultConsumer(results, &responded, &matched)
	go mainOutput(iter, &responded, &matched)
	go keepProgress(iter)

	block := make(chan bool)
	wg := sync.WaitGroup{}
	for i := 0; i < *workers; i++ {
		go func(id int) {
			wg.Add(1)
			<-block
			worker(id, iter, results, *verbose)
			wg.Done()
		}(i)
	}
	close(block)
	wg.Wait()
	time.Sleep(time.Second * 10)
}

func keepProgress(iter *addr.CIDR4RevIterator) {
	tick := time.NewTicker(time.Second * 10)
	for {
		f, err := os.OpenFile("progress.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_SYNC, 0777)
		if err != nil {
			panic("failed to open progress.log: " + err.Error())
		}
		current := iter.Counter()
		_, err = f.WriteString(fmt.Sprint(current))
		if err != nil {
			panic("failed to write progress.log: " + err.Error())
		}
		_ = f.Close()
		<-tick.C
	}
}

func resultConsumer(c chan ScanResult, responded *int, matched *int) {
	for {
		result := <-c
		*responded++
		log.Info().Logf("Server %s responded with: %s", result.ip, strconv.QuoteToASCII(result.response))

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
		fmt.Println("Skyfalls' Low Performance Single-threaded Server Scanner(TM)")
		fmt.Printf("Total ips: %d\n", iter.CountTotal())
		fmt.Printf("Current: %d - %s\n", iter.Counter(), iter.Current())
		fmt.Printf("Responded: %d Matched: %d\n", *responded, *matched)
		progress := float64(iter.Counter()) / float64(iter.CountTotal())
		elapsed := time.Now().Sub(t)
		fmt.Printf("Progress: %.2f%% | ETA: %s\n", progress*100, time.Duration(float64(elapsed.Nanoseconds())/progress))
		fmt.Printf("Time Elapsed: %s", elapsed)
		_ = <-tick.C
	}
}

func clear() {
	fmt.Print("\033[H\033[2J")
}
