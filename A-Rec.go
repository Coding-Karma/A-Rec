package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
)

var url string
var wg sync.WaitGroup
var ip string
var nsurl string

func nikto(outChan chan<- []byte) {
	cmd := exec.Command("nikto", "-h", url)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}

func whois(outChan chan<- []byte) {
	//    set := exec.Command("figlet","whois")
	//    set.Stdout = os.Stdout
	nsurl = url[12:]
	cmd := exec.Command("whois", nsurl)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func nmap(outChan chan<- []byte) {
	cmd := exec.Command("nmap", "-sC", "-sV", "-oA", "nmap", ip)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func sniper(outChan chan<- []byte) {
	cmd := exec.Command("sniper", "-t", url)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func sublist3r(outChan chan<- []byte) {
	nsurl = url[12:]
	cmd := exec.Command("sublist3r", "-d", nsurl)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}

func inspy(outChan chan<- []byte) {
	cmd := exec.Command("inspy", "--empspy", "/opt/wordlists/wordlists/title-list-large.txt", url)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func wig(outChan chan<- []byte) {
	cmd := exec.Command("wig", url)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func dnsenum(outChan chan<- []byte) {
	nsurl = url[12:]
	cmd := exec.Command("dnsenum", nsurl)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func httrack(outChan chan<- []byte) {
	cmd := exec.Command("httrack", url)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func dnsrecon(outChan chan<- []byte) {
	nsurl = url[12:]
	cmd := exec.Command("dnsrecon", "-d", nsurl)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func dmitry(outChan chan<- []byte) {
	nsurl = url[12:]
	cmd := exec.Command("dmitry", nsurl)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func blackwidow(outChan chan<- []byte) {
	nsurl = url[12:]
	cmd := exec.Command("/opt/Blackwidow/blackwidow", "-u", url)
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func angryfuzz(outChan chan<- []byte) {
	cmd := exec.Command("/opt/angryfuzzer/angryFuzzer.py", "-u", url, "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}
func snitch(outChan chan<- []byte) {
	cmd := exec.Command("/opt/snitch/snitch.py", "--url", url, "-D", "ext")
	bs, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	outChan <- bs
	wg.Done()
}

func main() {
	f, err := os.OpenFile("reports.txt", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	log.SetOutput(f)
	outChan := make(chan []byte)
	fmt.Printf("Please input URL with https:// \n")
	fmt.Scanln(&url)
	fmt.Printf("Please input IP \n")
	fmt.Scanln(&ip)
	wg.Add(1)
	go nikto(outChan)
	wg.Add(1)
	go whois(outChan)
	wg.Add(1)
	go nmap(outChan)
	wg.Add(1)
	go sniper(outChan)
	wg.Add(1)
	go sublist3r(outChan)
	wg.Add(1)
	go inspy(outChan)
	wg.Add(1)
	go wig(outChan)
	wg.Add(1)
	go dnsenum(outChan)
	wg.Add(1)
	go httrack(outChan)
	wg.Add(1)
	go dnsrecon(outChan)
	wg.Add(1)
	go dmitry(outChan)
	wg.Add(1)
	go blackwidow(outChan)
	wg.Add(1)
	go angryfuzz(outChan)
	wg.Add(1)
	go snitch(outChan)
	for i := 0; i < 14; i++ {
		bs := <-outChan
		fmt.Println(string(bs))
		log.Println(string(bs))

	}

	close(outChan)
	wg.Wait()
}
