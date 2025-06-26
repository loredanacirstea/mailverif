package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"slices"
	"strings"
)

type Header struct {
	Key   string // Key in original case.
	LKey  string // Key in lower-case, for canonical case.
	Value []byte // Literal header value, possibly spanning multiple lines, not modified in any way, including crlf, excluding leading key and colon.
	Raw   []byte // Like value, but including original leading key and colon. Ready for use as simple header canonicalized use.
}

func ParseHeaders(br *bufio.Reader) ([]Header, int, error) {
	var o int
	var l []Header
	var key, lkey string
	var value []byte
	var raw []byte
	for {
		line, err := readline(br)
		if err != nil {
			return nil, 0, err
		}
		o += len(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(l) == 0 && key == "" {
				return nil, 0, fmt.Errorf("malformed message, starts with space/tab")
			}
			value = append(value, line...)
			raw = append(raw, line...)
			continue
		}
		if key != "" {
			l = append(l, Header{key, lkey, value, raw})
		}
		t := bytes.SplitN(line, []byte(":"), 2)
		if len(t) != 2 {
			return nil, 0, fmt.Errorf("malformed message, header without colon")
		}

		key = strings.TrimRight(string(t[0]), " \t") // todo: where is this specified?
		// Check for valid characters. ../rfc/5322:1689 ../rfc/6532:193
		for _, c := range key {
			if c <= ' ' || c >= 0x7f {
				return nil, 0, fmt.Errorf("invalid header field name")
			}
		}
		if key == "" {
			return nil, 0, fmt.Errorf("empty header key")
		}
		lkey = strings.ToLower(key)
		value = slices.Clone(t[1])
		raw = slices.Clone(line)
	}
	if key != "" {
		l = append(l, Header{key, lkey, value, raw})
	}
	return l, o, nil
}

func readline(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if bytes.HasSuffix(line, []byte("\r\n")) {
			if len(buf) == 0 {
				return line, nil
			}
			return append(buf, line...), nil
		}
		buf = append(buf, line...)
	}
}
