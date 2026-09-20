package ports

import "testing"

func TestHexToIPv4(t *testing.T) {
	cases := map[string]string{ // /proc hex (little-endian) -> expected IP
		"0100007F": "127.0.0.1",
		"00000000": "0.0.0.0",
		"0A01A8C0": "192.168.1.10", // C0 A8 01 0A reversed -> 192.168.1.10
	}
	for in, want := range cases {
		got, err := hexToIPv4(in)
		if err != nil || got.String() != want {
			t.Errorf("hexToIPv4(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
}

func TestHexToIPv6(t *testing.T) {
	cases := map[string]string{ // /proc hex (per-word little-endian) -> expected IP
		"00000000000000000000000001000000": "::1",
		"B80D0120000000000000000001000000": "2001:db8::1",
	}
	for in, want := range cases {
		got, err := hexToIPv6(in)
		if err != nil || got.String() != want {
			t.Errorf("hexToIPv6(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
}

func TestParseHexPort(t *testing.T) {
	cases := map[string]int{ // hex (big-endian) -> port
		"0035": 53,
		"1F90": 8080,
		"1538": 5432,
	}
	for in, want := range cases {
		got, err := parseHexPort(in)
		if err != nil || got != want {
			t.Errorf("parseHexPort(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}

func TestParseProcNet(t *testing.T) {
	// A fixture mimicking /proc/net/tcp: a header line (skipped), two LISTEN
	// sockets (state 0A) that should be returned, and one ESTABLISHED socket
	// (state 01) that should be filtered out.
	fixture := "" +
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0\n" +
		"   2: 00000000:270F 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0\n"

	got, err := parseProcNet("tcp", []byte(fixture))
	if err != nil {
		t.Fatalf("parseProcNet returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 listening sockets (established one filtered out), got %d: %+v", len(got), got)
	}

	// Row 0: 0.0.0.0:8080
	if got[0].IP.String() != "0.0.0.0" || got[0].Port != 8080 || got[0].Inode != "12345" {
		t.Errorf("socket[0] = %s:%d inode=%s; want 0.0.0.0:8080 inode=12345",
			got[0].IP, got[0].Port, got[0].Inode)
	}
	// Row 1: 127.0.0.1:5432
	if got[1].IP.String() != "127.0.0.1" || got[1].Port != 5432 || got[1].Inode != "67890" {
		t.Errorf("socket[1] = %s:%d inode=%s; want 127.0.0.1:5432 inode=67890",
			got[1].IP, got[1].Port, got[1].Inode)
	}
}
