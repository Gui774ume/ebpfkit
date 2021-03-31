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
