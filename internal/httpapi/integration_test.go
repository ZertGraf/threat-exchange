package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"threat-exchange/api"
	"threat-exchange/internal/store"
	"threat-exchange/internal/testdb"
)

func openTestStore(t *testing.T, databaseURL string) *store.Postgres {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repo, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	return repo
}

func send(t *testing.T, client *http.Client, base, method, path, body string, expected int) api.ThreatResponse {
	t.Helper()
	req, err := http.NewRequest(method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", testKey)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expected {
		t.Fatalf("%s %s: got %d, want %d: %s", method, path, response.StatusCode, expected, data)
	}
	if expected >= 400 {
		var problem api.ErrorResponse
		if err := json.Unmarshal(data, &problem); err != nil || problem.Message == "" {
			t.Fatalf("invalid error: %s", data)
		}
		return api.ThreatResponse{}
	}
	if expected == 201 && response.Header.Get("Location") != "/info/"+testMD5 {
		t.Fatal("invalid location header")
	}
	var result api.ThreatResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.CreatedAt.IsZero() || result.UpdatedAt.IsZero() || result.Tags == nil {
		t.Fatalf("incomplete response: %s", data)
	}
	return result
}

func TestPostgresLifecycle(t *testing.T) {
	databaseURL, _ := testdb.Isolated(t)
	repo := openTestStore(t, databaseURL)
	server := httptest.NewTLSServer(newTestHandler(t, repo, Options{APIKey: testKey}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 10 * time.Second
	path := "/info/" + testMD5
	send(t, client, server.URL, "GET", path, "", 404)
	send(t, client, server.URL, "PUT", path, `{"name":"missing"}`, 404)
	created := send(t, client, server.URL, "POST", "/info",
		`{"md5":"`+strings.ToUpper(testMD5)+`","name":"  Trojan.Win32.Generic  ","description":"sample analysis","severity":"high","type":"trojan","tags":["windows","banking"]}`, 201)
	if created.Md5 != testMD5 || created.Name != "Trojan.Win32.Generic" || created.Severity != api.SeverityHigh || created.Type != api.ThreatTypeTrojan || len(created.Tags) != 2 {
		t.Fatalf("incorrect creation: %+v", created)
	}
	read := send(t, client, server.URL, "GET", "/info/"+strings.ToUpper(testMD5), "", 200)
	if !reflect.DeepEqual(created, read) {
		t.Fatalf("read differs: %+v versus %+v", read, created)
	}
	send(t, client, server.URL, "POST", "/info", `{"md5":"`+testMD5+`","name":"duplicate"}`, 409)
	replaced := send(t, client, server.URL, "PUT", path, "{\"name\":\"\\u00a0\\u2003Trojan.Updated\\u3000\"}", 200)
	if replaced.Name != "Trojan.Updated" || replaced.Description != "" || replaced.Severity != api.SeverityUnknown || replaced.Type != api.ThreatTypeUnknown || len(replaced.Tags) != 0 || !replaced.CreatedAt.Equal(created.CreatedAt) || replaced.UpdatedAt.Before(created.UpdatedAt) {
		t.Fatalf("incorrect replacement: %+v", replaced)
	}
	send(t, client, server.URL, "PUT", path, `{"name":"invalid","severity":"bad"}`, 400)
	unchanged := send(t, client, server.URL, "GET", path, "", 200)
	if !reflect.DeepEqual(unchanged, replaced) {
		t.Fatal("rejected request mutated persisted data")
	}
	server.Close()
	repo.Close()
	restarted := openTestStore(t, databaseURL)
	newServer := httptest.NewTLSServer(newTestHandler(t, restarted, Options{APIKey: testKey}))
	t.Cleanup(newServer.Close)
	read = send(t, newServer.Client(), newServer.URL, "GET", path, "", 200)
	if !reflect.DeepEqual(read, replaced) {
		t.Fatal("data did not survive store and server restart")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := restarted.Get(ctx, testMD5); err == nil {
		t.Fatal("database ignored cancellation")
	}
}

func TestPostgresConcurrentUniqueness(t *testing.T) {
	databaseURL, _ := testdb.Isolated(t)
	repo := openTestStore(t, databaseURL)
	other := openTestStore(t, databaseURL)
	servers := []*httptest.Server{
		httptest.NewServer(newTestHandler(t, repo, Options{})),
		httptest.NewServer(newTestHandler(t, other, Options{})),
	}
	for _, server := range servers {
		t.Cleanup(server.Close)
	}
	const count = 24
	statuses := make(chan int, count)
	failures := make(chan error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"md5":"` + testMD5 + `","name":"concurrent"}`
			if i%2 == 0 {
				body = `{"md5":"` + strings.ToUpper(testMD5) + `","name":"concurrent"}`
			}
			client := &http.Client{Timeout: 10 * time.Second}
			response, err := client.Post(servers[i%2].URL+"/info", "application/json", strings.NewReader(body))
			if err != nil {
				failures <- err
				return
			}
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				failures <- err
			}
			if err := response.Body.Close(); err != nil {
				failures <- err
			}
			statuses <- response.StatusCode
		}(i)
	}
	wg.Wait()
	close(statuses)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	created, conflicts := 0, 0
	for status := range statuses {
		switch status {
		case 201:
			created++
		case 409:
			conflicts++
		default:
			t.Errorf("unexpected status %d", status)
		}
	}
	if created != 1 || conflicts != count-1 {
		t.Fatalf("created %d, conflicts %d; want 1 and %d", created, conflicts, count-1)
	}
}

func TestConcurrentSchemaInitialization(t *testing.T) {
	databaseURL, _ := testdb.Isolated(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			repo, err := store.Open(ctx, databaseURL)
			if err != nil {
				t.Error(fmt.Errorf("concurrent startup: %w", err))
				return
			}
			repo.Close()
		}()
	}
	wg.Wait()
}

func TestPostgresReadiness(t *testing.T) {
	databaseURL, _ := testdb.Isolated(t)
	repo := openTestStore(t, databaseURL)
	for _, want := range []int{200, 503} {
		if want == 503 {
			repo.Close()
		}
		// a fresh handler starts without a cached readiness result.
		handler := newTestHandler(t, repo, Options{APIKey: testKey})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		if w.Code != want || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("readiness status=%d want=%d: %s", w.Code, want, w.Body)
		}
	}
}

func TestPostgresSlowUpload(t *testing.T) {
	databaseURL, _ := testdb.Isolated(t)
	repo := openTestStore(t, databaseURL)
	server := httptest.NewUnstartedServer(newTestHandler(t, repo, Options{}))
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 20 * time.Second
	server.Start()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 12 * time.Second
	send(t, client, server.URL, "POST", "/info", "{\"md5\":\""+testMD5+"\",\"name\":\"before\"}", 201)
	reader, writer := io.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		<-done
	})
	go func() {
		defer close(done)
		defer func() {
			if err := writer.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err := io.WriteString(writer, "{\"name\":\""); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(5200 * time.Millisecond)
		if _, err := io.WriteString(writer, "after\"}"); err != nil {
			t.Error(err)
		}
	}()
	request, err := http.NewRequest("PUT", server.URL+"/info/"+testMD5, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if response.StatusCode != 200 {
		t.Fatalf("slow upload status=%d: %s", response.StatusCode, body)
	}
	if record := send(t, client, server.URL, "GET", "/info/"+testMD5, "", 200); record.Name != "after" {
		t.Fatal("slow upload was not persisted")
	}
}
