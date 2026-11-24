package main

import "testing"

func TestTCPDrainAndWithdrawal(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
