package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type OutputRow struct {
	Domain         string
	IPAddress      string
	Port           string
	Protocol       string
	ResponseStatus string
	RespSize       int
	Headers        string
	Body           string
}

var portsToProbe = []string{"80", "443"}

func probeDomain(domain string, port string, protocol string, wg *sync.WaitGroup, output chan OutputRow, unresolvedOutput chan string) {
	defer wg.Done()

	ipAddr, errLookup := net.LookupIP(domain)
	if errLookup != nil {
		unresolvedOutput <- domain
		return
	}

	url := fmt.Sprintf("%s://%s:%s", protocol, domain, port)
	client := http.Client{
		Timeout: time.Second * 60,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1")

	resp, err := client.Do(req)

	status := "null"
	if err != nil {
		status = "unreachable"
	} else {
		status = fmt.Sprint(resp.StatusCode)
		defer resp.Body.Close()
	}

	headers := "null"
	if resp != nil {
		headerList := make([]string, 0)
		for k, v := range resp.Header {
			headerValues := strings.Join(v, "</br>")
			headerList = append(headerList, fmt.Sprintf(`%s:%s`, k, headerValues))
		}
		headers = strings.Join(headerList, ",")
	}

	body := "null"
	respSize := 0
	if resp != nil && err == nil {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			body = string(bodyBytes)
			respSize = len(bodyBytes)
		}
	}

	ip := ipAddr[0].String()

	output <- OutputRow{
		Domain:         domain,
		IPAddress:      ip,
		Port:           port,
		Protocol:       protocol,
		ResponseStatus: status,
		RespSize:       respSize,
		Headers:        headers,
		Body:           body,
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./triager <domains_file>")
		os.Exit(1)
	}

	// Create a log file
	logFile, err := os.OpenFile("triager_error_log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	// Set log output to the file
	log.SetOutput(logFile)

	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	output := make(chan OutputRow, 100)
	unresolvedOutput := make(chan string, 100)
	done := make(chan bool)

	var wg sync.WaitGroup

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		for _, port := range portsToProbe {
			if port == "80" {
				wg.Add(1)
				go probeDomain(domain, port, "http", &wg, output, unresolvedOutput)
			} else if port == "443" {
				wg.Add(1)
				go probeDomain(domain, port, "https", &wg, output, unresolvedOutput)
			} else {
				wg.Add(2)
				go probeDomain(domain, port, "http", &wg, output, unresolvedOutput)
				go probeDomain(domain, port, "https", &wg, output, unresolvedOutput)
			}
		}
	}

	go func() {
		wg.Wait()
		close(output)
		close(unresolvedOutput)
		done <- true
	}()

	db, err := sql.Open("mysql", "root:kali@tcp(localhost:3306)/bughunter")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO hosts(domain, ip_address, port, proto, httprescode, httpheader, httpbody, respsize, date) VALUES(?, ?, ?, ?, ?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE ip_address=VALUES(ip_address), port=VALUES(port), proto=VALUES(proto), httprescode=VALUES(httprescode), httpheader=VALUES(httpheader), httpbody=VALUES(httpbody), respsize=VALUES(respsize), date=VALUES(date)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	unresolvedDomains := make(map[string]bool)
	unresolvedFile, err := os.Create("unresolved_domains.txt")
	if err != nil {
		log.Printf("Error creating unresolved domains file: %v\n", err)
		os.Exit(1)
	}
	defer unresolvedFile.Close()

	for {
		select {
		case row, ok := <-output:
			if !ok {
				output = nil
				break
			}
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%d\n", row.Domain, row.IPAddress, row.Port, row.Protocol, row.ResponseStatus, row.Headers, row.Body, row.RespSize)

			_, err := stmt.Exec(row.Domain, row.IPAddress, row.Port, row.Protocol, row.ResponseStatus, row.Headers, row.Body, row.RespSize)
			if err != nil {
				log.Printf("Error inserting row into database: %v\n", err)
			}

		case domain, ok := <-unresolvedOutput:
			if !ok {
				unresolvedOutput = nil
				break
			}
			unresolvedDomains[domain] = true
			unresolvedFile.WriteString(domain + "\n")
		}

		if output == nil && unresolvedOutput == nil {
			break
		}
	}

	<-done
}
