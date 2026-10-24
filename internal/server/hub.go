package server

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// event is one message on the event stream.
type event struct {
	ID   int64 // 0 for events that are not kept for replay
	Type string
	Data []byte // JSON
}

// hub fans events out to every connected page. It keeps the last events so a
// page that reconnects can catch up from the last ID it saw. Frequent progress
// events are sent but not kept.
type hub struct {
	mu     sync.Mutex
	nextID int64
	keep   int
	kept   []event
	subs   map[chan event]bool
}

func newHub(keep int) *hub {
	return &hub{keep: keep, subs: make(map[chan event]bool)}
}

// publish sends v as JSON to every subscriber, and keeps it for replay if
// replay is set.
func (h *hub) publish(typ string, v any, replay bool) {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("server: event %s: %v", typ, err))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := event{Type: typ, Data: data}
	if replay {
		h.nextID++
		e.ID = h.nextID
		h.kept = append(h.kept, e)
		if len(h.kept) > h.keep {
			h.kept = h.kept[len(h.kept)-h.keep:]
		}
	}
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
			// Too slow to keep up: drop it. The page reconnects and replays.
			close(ch)
			delete(h.subs, ch)
		}
	}
}

// subscribe returns the kept events after the given ID, a channel for new
// ones, and a function that ends the subscription.
func (h *hub) subscribe(after int64) ([]event, <-chan event, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var replay []event
	if after > 0 {
		for _, e := range h.kept {
			if e.ID > after {
				replay = append(replay, e)
			}
		}
	}
	ch := make(chan event, 256)
	h.subs[ch] = true
	return replay, ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.subs[ch] {
			close(ch)
			delete(h.subs, ch)
		}
	}
}

// close ends every subscription, so open event streams finish.
func (h *hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		close(ch)
		delete(h.subs, ch)
	}
}

// writeEvent writes e in the text/event-stream format.
func writeEvent(w io.Writer, e event) error {
	if e.ID > 0 {
		if _, err := fmt.Fprintf(w, "id: %d\n", e.ID); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, e.Data)
	return err
}
