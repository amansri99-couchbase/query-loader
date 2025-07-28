package main

import (
	"crypto/x509" // Added for handling certificates
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/couchbase/gocb/v2"
)

// --- Configuration ---
const (
	SCRIPT_VERSION                 = "V12_SUCCESS_RATE_CALCS"
	numWorkers                     = 10
	conflictErrorCode       uint32 = 12009
	requestAbortedErrorCode uint32 = 1195
)

// --- Capella Certificate ---
// This is the required root certificate to establish a trusted TLS connection.
const ca = `-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIQTRgE9XKQCjb4/8v+xZpVNjANBgkqhkiG9w0BAQsFADBP
MRIwEAYDVQQKDAlDb3VjaGJhc2UxDjAMBgNVBAsMBUNsb3VkMRMwEQYDVQQIDApD
YWxpZm9ybmlhMRQwEgYDVQQHDAtTYW50YSBDbGFyYTAeFw0yMDAzMDIxMTA1MzFa
Fw0zMDAyMjcxMjA1MzFaME8xEjAQBgNVBAoMCUNvdWNoYmFzZTEOMAwGA1UECwwF
Q2xvdWQxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC1NhbnRhIENsYXJh
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApqJoqm1WW7HHWgliuGCL
f2EgV9Yz0rCE7WW64zUUjKk1Zsi/Y4TqkiZTPFjvY+GIFMroOoYqPeQ8rWlyhG1K
rjQk8OnDXX+NHVOdG2vLtAIkq9Tlu3+BTtcDliacyLmXuxP4wRuD34I18hUeBVAp
E1+UX4Z+OdFN0caCipr5wgrWganBiIf3rBQLtZIJVmkU/voopysH9ZPWC7lP7KqQ
3yx1874rL0SbKO+N6B7cDiGAJNS7QnyN+OWUPb8QaahPk6wF4I36SLQOtMJ2pTqb
JcI3/9WBo0Isc1TXIJfZe/CVsYveyp3LyjXE2sJJ7MDUxdOg+gUkjii2haPrtQPP
xwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS9KVI2sXz9ZLEZ
qLibqJyCls964TAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAHvY
LhEsZjCU26xFWwe5pFwVE2KGxUDiObHMUdxaZGVDhV9/w6Ft2rlXyU/nW7WyT+cR
/WHAF5FN6AHVCsB2FoKcWhUSdxoL2nkFbbf5JU5hQh8CoEg7kaAYTgKtg2D6LudE
gAwwzG7cqQaKT0D122YRTTyqznARzgcdUnQ+9LaWXV4IRlttz9eWT4RCS3UjvAHq
huhJe84O/Ln4TvKJ/7ZqU7nL4is2Njf6y1qddcTDCbGPiY/K7xM+noGUeiHZGRVk
/7N2Go2eyqzKn4FmD8Qhf79JPPnAJ7sckBQystaTcPv+jnOZy8xX4l81XxP2V8qV
P266iXg2HvJ26UEP/pI=
-----END CERTIFICATE-----

`

// --- Outcome Constants for Categorization ---
const (
	OutcomeSuccess = "Success"
	OutcomeFailure = "Failure"

	OutcomeConflict = "Conflict"
)

// QueryInfo holds the details of a query to be executed.
type QueryInfo struct {
	Name   string
	Query  string
	Params map[string]interface{}
}

// QueryResult uses an Outcome string for better categorization.
type QueryResult struct {
	Name     string
	Outcome  string
	ErrorMsg string
}

// StatCounter holds the categorized results.
type StatCounter struct {
	Success   int
	Conflicts int
	Failures  map[string]int
}

// FileLogger is a custom logger that satisfies the gocb.Logger interface
// and writes logs to a file using the standard log package.
type FileLogger struct {
	logger *log.Logger
}

// Log is the only method required to satisfy the gocb.Logger interface.
func (l *FileLogger) Log(level gocb.LogLevel, offset int, format string, v ...interface{}) error {
	l.logger.Printf(format, v...)
	return nil
}

// NewStatCounter initializes a new StatCounter.
func NewStatCounter() *StatCounter {
	return &StatCounter{
		Failures: make(map[string]int),
	}
}

// handleQueryError is a helper function to categorize errors correctly.
func handleQueryError(id int, task QueryInfo, err error, appLogger *log.Logger) QueryResult {
	var queryErr *gocb.QueryError
	if errors.As(err, &queryErr) {
		isOnlyConflicts := true
		if len(queryErr.Errors) == 0 {
			isOnlyConflicts = false
		} else {
			for _, e := range queryErr.Errors {
				if e.Code != conflictErrorCode && e.Code != requestAbortedErrorCode {
					isOnlyConflicts = false
					break
				}
			}
		}

		if isOnlyConflicts {
			appLogger.Printf("APP: Worker %d recorded a CONFLICT on query '%s'", id, task.Name)
			return QueryResult{Name: task.Name, Outcome: OutcomeConflict}
		} else {
			errorJSON, jsonErr := json.Marshal(queryErr)
			var errorMsg string
			if jsonErr != nil {
				errorMsg = fmt.Sprintf("Failed to marshal query error json: %v", queryErr)
			} else {
				errorMsg = string(errorJSON)
			}
			appLogger.Printf("APP: Worker %d recorded a FAILURE on query '%s': %s", id, task.Name, errorMsg)
			return QueryResult{Name: task.Name, Outcome: OutcomeFailure, ErrorMsg: errorMsg}
		}
	} else {
		appLogger.Printf("APP: Worker %d recorded a FAILURE on query '%s': %s", id, task.Name, err.Error())
		return QueryResult{Name: task.Name, Outcome: OutcomeFailure, ErrorMsg: err.Error()}
	}
}

func main() {
	// --- App Log File Setup ---
	appLogFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("FATAL: Failed to open app log file: %v\n", err)
		os.Exit(1)
	}
	defer appLogFile.Close()
	appLogger := log.New(appLogFile, "APP: ", log.LstdFlags)

	// --- SDK Log File Setup ---
	sdkLogFile, err := os.OpenFile("sdk.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("FATAL: Failed to open sdk log file: %v\n", err)
		os.Exit(1)
	}
	defer sdkLogFile.Close()
	sdkStdLogger := log.New(sdkLogFile, "SDK: ", log.LstdFlags)
	sdkCustomLogger := &FileLogger{logger: sdkStdLogger}
	gocb.SetLogger(sdkCustomLogger)

	// --- Couchbase Capella Connection Details ---
	connectionString := "couchbases://private-endpoint.1tsdvautcakfccur.sandbox.nonprod-project-avengers.com"
	username := "admin"
	password := "Password@123"
	bucketName := "travel-sample"
	scopeName := "inventory"

	// Create a certificate pool and add the Capella CA certificate.
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(ca)); !ok {
		fmt.Println("FATAL: Failed to append CA certificate")
		os.Exit(1)
	}

	// --- Initialize Couchbase Cluster Connection ---
	options := gocb.ClusterOptions{
		Authenticator: gocb.PasswordAuthenticator{
			Username: username,
			Password: password,
		},
		SecurityConfig: gocb.SecurityConfig{
			TLSRootCAs: certPool,
		},
	}

	cluster, err := gocb.Connect(connectionString, options)
	if err != nil {
		fmt.Printf("FATAL: Failed to connect to cluster: %v\n", err)
		os.Exit(1)
	}
	defer cluster.Close(nil)

	bucket := cluster.Bucket(bucketName)
	if err = bucket.WaitUntilReady(30*time.Second, nil); err != nil {
		fmt.Printf("FATAL: Failed to wait until bucket ready: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(
		"--- Starting concurrent query execution (SCRIPT VERSION: %s) with %d workers ---\n",
		SCRIPT_VERSION,
		numWorkers,
	)

	// --- Define Queries ---
	selectQueries := []QueryInfo{
		{Name: "Query 1 (Airline by ICAO)", Query: `SELECT name, iata, icao, callsign, country FROM ` + "`" + bucketName + "`" + `.` + scopeName + `.airline WHERE icao = 'UAL';`},
		{Name: "Query 2 (Airport by FAA)", Query: `SELECT airportname, city, country, faa FROM ` + "`" + bucketName + "`" + `.` + scopeName + `.airport WHERE faa = 'LAX';`},
		{Name: "Query 3 (All Routes)", Query: `SELECT sourceairport, destinationairport, airline, stops, schedule FROM ` + "`" + bucketName + "`" + `.` + scopeName + `.route LIMIT 20;`},
		{Name: "Query 4 (Hotels in US)", Query: `SELECT name, city, country, address, description FROM ` + "`" + bucketName + "`" + `.` + scopeName + `.hotel WHERE country = 'United States' LIMIT 20;`},
	}
	updateHotelCities := []string{"London", "Paris", "New York", "San Francisco", "Tokyo", "Los Angeles"}
	updateAirlineKeys := []string{"airline_8091", "airline_5225", "airline_137", "airline_410", "airline_24", "airline_10"}
	var queryCounter uint64 = 0

	tasks := make(chan QueryInfo, numWorkers*2)
	results := make(chan QueryResult, numWorkers*2)

	var wg sync.WaitGroup
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		// --- WORKER LOGIC ---
		go func(id int) {
			defer wg.Done()

			for task := range tasks {
				queryOpts := &gocb.QueryOptions{NamedParameters: task.Params}
				rows, err := cluster.Query(task.Query, queryOpts)

				if err != nil {
					results <- handleQueryError(id, task, err, appLogger)
					continue
				}

				var row map[string]interface{}
				for rows.Next() {
					_ = rows.Row(&row)
				}

				if err := rows.Err(); err != nil {
					results <- handleQueryError(id, task, err, appLogger)
				} else {
					results <- QueryResult{Name: task.Name, Outcome: OutcomeSuccess}
				}
			}
		}(w)
	}

	// --- Goroutine to collect categorized results ---
	queryStats := make(map[string]*StatCounter)
	allQueries := append(selectQueries, QueryInfo{Name: "Query 5 (Update Airline)"}, QueryInfo{Name: "Query 6 (Update Hotels)"})
	for _, q := range allQueries {
		queryStats[q.Name] = NewStatCounter()
	}

	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for result := range results {
			stats := queryStats[result.Name]
			switch result.Outcome {
			case OutcomeSuccess:
				stats.Success++
			case OutcomeConflict:
				stats.Conflicts++
			case OutcomeFailure:
				stats.Failures[result.ErrorMsg]++
			}
		}
	}()

	// --- Main loop to dispatch jobs ---
	startTime := time.Now()
	duration := 15 * time.Minute
	totalQueriesDispatched := 0

	for time.Since(startTime) < duration {
		for _, q := range selectQueries {
			tasks <- q
			totalQueriesDispatched++
		}
		queryCounter++
		airlineKey := updateAirlineKeys[queryCounter%uint64(len(updateAirlineKeys))]
		tasks <- QueryInfo{Name: "Query 5 (Update Airline)", Query: `UPDATE ` + "`" + bucketName + "`" + `.` + scopeName + `.airline USE KEYS $id SET name = 'Couchbase Global Airways' RETURNING META().id;`, Params: map[string]interface{}{"id": airlineKey}}
		totalQueriesDispatched++
		targetCity := updateHotelCities[queryCounter%uint64(len(updateHotelCities))]
		tasks <- QueryInfo{Name: "Query 6 (Update Hotels)", Query: `UPDATE ` + "`" + bucketName + "`" + `.` + scopeName + `.hotel SET amenities = ARRAY_APPEND(IFMISSING(amenities, []), 'Free WiFi') WHERE city = $city RETURNING META().id;`, Params: map[string]interface{}{"city": targetCity}}
		totalQueriesDispatched++
	}
	fmt.Println("\n--- Time limit reached. Waiting for workers to finish... ---")

	close(tasks)
	wg.Wait()
	close(results)
	resultsWg.Wait()

	// --- Final Summary ---
	elapsedSeconds := time.Since(startTime).Seconds()
	fmt.Println("\n--- Query Execution Summary ---")

	overallSuccess := 0
	overallConflicts := 0
	overallFailures := make(map[string]int)

	for queryName, stats := range queryStats {
		totalFailures := 0
		for _, count := range stats.Failures {
			totalFailures += count
		}
		totalAttempts := stats.Success + stats.Conflicts + totalFailures
		overallSuccess += stats.Success
		overallConflicts += stats.Conflicts
		for errType, count := range stats.Failures {
			overallFailures[errType] += count
		}

		// **MODIFIED**: Calculate the two different success rates.
		var successRateWithConflictsAsFailures float64
		if totalAttempts > 0 {
			successRateWithConflictsAsFailures = (float64(stats.Success) / float64(totalAttempts)) * 100
		}

		var successRateIgnoringConflicts float64
		totalAttemptsIgnoringConflicts := stats.Success + totalFailures
		if totalAttemptsIgnoringConflicts > 0 {
			successRateIgnoringConflicts = (float64(stats.Success) / float64(totalAttemptsIgnoringConflicts)) * 100
		}

		// **MODIFIED**: Updated print format for clarity.
		fmt.Printf(
			"\n%s: Successes=%d, Conflicts=%d, Failures=%d, Total=%d\n",
			queryName, stats.Success, stats.Conflicts, totalFailures, totalAttempts,
		)
		fmt.Printf("    ├─ Success Rate (conflicts as failures): %.2f%%\n", successRateWithConflictsAsFailures)
		fmt.Printf("    └─ Success Rate (conflicts ignored):      %.2f%%\n", successRateIgnoringConflicts)

		if totalFailures > 0 {
			fmt.Println("    └─ Failure Breakdown:")
			for errMsg, count := range stats.Failures {
				fmt.Printf("        - [%d times] %s\n", count, errMsg)
			}
		}
	}

	totalOverallFailures := 0
	for _, count := range overallFailures {
		totalOverallFailures += count
	}
	overallAttempts := overallSuccess + overallConflicts + totalOverallFailures

	// **MODIFIED**: Calculate the two different overall success rates.
	var overallSuccessRateWithConflictsAsFailures float64
	if overallAttempts > 0 {
		overallSuccessRateWithConflictsAsFailures = (float64(overallSuccess) / float64(overallAttempts)) * 100
	}

	var overallSuccessRateIgnoringConflicts float64
	overallAttemptsIgnoringConflicts := overallSuccess + totalOverallFailures
	if overallAttemptsIgnoringConflicts > 0 {
		overallSuccessRateIgnoringConflicts = (float64(overallSuccess) / float64(overallAttemptsIgnoringConflicts)) * 100
	}

	// **MODIFIED**: Updated overall print format for clarity.
	fmt.Printf("\n--- Overall Summary ---\n")
	fmt.Printf("Totals: Successes=%d, Conflicts=%d, Failures=%d, Total Attempts=%d\n",
		overallSuccess, overallConflicts, totalOverallFailures, overallAttempts)
	fmt.Printf("    ├─ Overall Success Rate (conflicts as failures): %.2f%%\n", overallSuccessRateWithConflictsAsFailures)
	fmt.Printf("    └─ Overall Success Rate (conflicts ignored):      %.2f%%\n", overallSuccessRateIgnoringConflicts)

	qps := float64(totalQueriesDispatched) / elapsedSeconds
	fmt.Printf("\nTotal Queries Dispatched: %d in %.2f seconds\n", totalQueriesDispatched, elapsedSeconds)
	fmt.Printf("Achieved QPS (Queries Per Second): %.2f\n", qps)

	fmt.Println("\nCluster connection closed.")
}
