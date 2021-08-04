/*
Copyright © 2021 GUILLAUME FOURNIER

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

import "time"

type Version struct {
	Version     string `json:"version"`
	Hash        string `json:"hash"`
	GitCommit   string `json:"git_commit"`
	ReleaseDate string `json:"release_date"`
}

type Message struct {
	APIVersion Version     `json:"api"`
	Timestamp  time.Time   `json:"timestamp"`
	Status     int         `json:"status"`
	Data       interface{} `json:"data"`
}

func NewMessage(data string, status int) Message {
	return Message{
		APIVersion: Version{
			Version:     APIVersion,
			Hash:        APIHash,
			GitCommit:   GitCommit,
			ReleaseDate: ReleaseDate,
		},
		Timestamp: time.Now(),
		Status:    status,
		Data:      data,
	}
}

type Product struct {
	Name    string `json:"name"`
	Price   int    `json:"price"`
	InStock int    `json:"in_stock"`
}

type Article struct {
	Name      string        `json:"name"`
	Timestamp time.Time     `json:"timestamp"`
	Author    string        `json:"author"`
	ReadTime  time.Duration `json:"read_time"`
}
