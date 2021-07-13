/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/gorilla/mux"
)

func main() {
	port := flag.Int("port", 8000, "port to use for the HTTP server")
	ip := flag.String("ip", "0.0.0.0", "ip on which to bind")
	flag.Parse()
	r := mux.NewRouter()
	r.HandleFunc("/healthcheck", HealthCheckHandler)
	r.HandleFunc("/api/products", ProductsHandler).Methods("POST")
	r.HandleFunc("/api/articles", ArticlesHandler)
	r.NotFoundHandler = NotFoundHandler()
	r.MethodNotAllowedHandler = MethodNotAllowedHandler()

	// Bind to a port and pass our router in
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *ip, *port), r))
}

func logPrefix(r *http.Request) string {
	var url string
	if r.URL != nil {
		url = r.URL.String()
	} else {
		url = r.RequestURI
	}

	return fmt.Sprintf("%s - %s %s", r.RemoteAddr, r.Method, url)
}

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	b, err := httputil.DumpRequest(r, true)
	if err == nil {
		log.Printf("%s", b)
	}

	data, _ := json.Marshal(NewMessage("OK", http.StatusOK))
	w.Write(data)
	log.Printf("%s - %d\n", logPrefix(r), http.StatusOK)
}

func ProductsHandler(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("%s - couldn't read request body !\n", logPrefix(r))
	}
	w.Write([]byte("Product ok !\n"))
	log.Printf("%s - (%d) %s - %d\n", logPrefix(r), len(data), string(data), http.StatusOK)
}

func ArticlesHandler(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("%s - couldn't read request body !\n", logPrefix(r))
	}
	w.Write([]byte("Articles ok !\n"))
	log.Printf("%s - (%d) %s - %d\n", logPrefix(r), len(data), string(data), http.StatusOK)
}

func NotFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s - %d\n", logPrefix(r), http.StatusNotFound)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	})
}

func MethodNotAllowedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s - %d\n", logPrefix(r), http.StatusMethodNotAllowed)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}
