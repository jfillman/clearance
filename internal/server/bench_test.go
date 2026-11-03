package server_test

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"testing"
	"time"
)

// BenchmarkEvaluationHTTP is POST /access/v1/evaluation end to end over HTTP (a keep-alive client, the auth
// middleware, strict decoding, the decision and its record committed) on store/memory, reporting p50 and p99 of
// single calls. The budget is 20 ms p99 end to end in-cluster (spec section 12).
func BenchmarkEvaluationHTTP(b *testing.B) {
	benchEvaluation(b, "")
}

// BenchmarkEvaluationHTTPPostgres is the same on store/pg (CLEARANCE_TEST_DSN; one durable commit per decision).
func BenchmarkEvaluationHTTPPostgres(b *testing.B) { benchEvaluation(b, pgDSN(b)) }

func benchEvaluation(b *testing.B, dsn string) {
	f := newFixture(b, config(b, dsn))
	bodies := [][]byte{request(b, prOpenAllowed, nil), request(b, prOpenDenied, nil), request(b, modelAllowed, nil)}
	client := f.srv.Client()
	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", f.srv.URL+"/access/v1/evaluation", bytes.NewReader(bodies[i%len(bodies)]))
		req.Header.Set("Authorization", "Bearer "+gw)
		t0 := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		lat = append(lat, time.Since(t0))
		if resp.StatusCode != 200 {
			b.Fatal(resp.StatusCode)
		}
	}
	b.StopTimer()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	q := func(p float64) float64 { return float64(lat[int(p*float64(len(lat)-1))].Microseconds()) }
	b.ReportMetric(q(0.50), "p50-us")
	b.ReportMetric(q(0.99), "p99-us")
	b.ReportMetric(q(1.0), "max-us")
}
