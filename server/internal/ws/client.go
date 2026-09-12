package ws

import (
	"context"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type client struct {
	hub    *Hub
	conn   *websocket.Conn
	id     string
	idMu   sync.RWMutex
	send   chan []byte
	dead   bool
	deadMu sync.Mutex
}

func (c *client) setID(id string) {
	c.idMu.Lock()
	c.id = id
	c.idMu.Unlock()
}

func (c *client) getID() string {
	c.idMu.RLock()
	defer c.idMu.RUnlock()
	return c.id
}

// enqueue blocks until there is room (bounded channel gives backpressure).
func (c *client) enqueue(b []byte) {
	select {
	case c.send <- b:
	case <-time.After(writeTimeout):
		c.close()
	}
}

// tryEnqueue is non-blocking; eternally slow consumers are dropped to protect
// the rest of the mesh.
func (c *client) tryEnqueue(b []byte) {
	select {
	case c.send <- b:
	default:
		c.close()
	}
}

func (c *client) close() {
	c.deadMu.Lock()
	if !c.dead {
		c.dead = true
		close(c.send)
	}
	c.deadMu.Unlock()
}

func (c *client) writePump() {
	ticker := time.NewTicker(pingEvery)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	}()
	for {
		select {
		case b, ok := <-c.send:
			if !ok {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			err := c.conn.Write(ctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				return
			}
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			err := c.conn.Ping(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
