package main

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestReplayCacheDetectsDuplicate(t *testing.T) {
	rc := newReplayCache(time.Minute)
	ecPub := make([]byte, 32)
	rand.Read(ecPub)

	if rc.checkAndRemember(ecPub) {
		t.Fatal("first sighting reported as replay")
	}
	if !rc.checkAndRemember(ecPub) {
		t.Fatal("second sighting of the same ecPub not detected as replay")
	}
}

func TestReplayCacheDistinctKeysIndependent(t *testing.T) {
	rc := newReplayCache(time.Minute)
	a := make([]byte, 32)
	b := make([]byte, 32)
	rand.Read(a)
	rand.Read(b)

	if rc.checkAndRemember(a) {
		t.Fatal("first sighting of a reported as replay")
	}
	if rc.checkAndRemember(b) {
		t.Fatal("first sighting of distinct key b reported as replay")
	}
}

func TestReplayCacheExpiresAfterWindow(t *testing.T) {
	rc := newReplayCache(20 * time.Millisecond)
	ecPub := make([]byte, 32)
	rand.Read(ecPub)

	if rc.checkAndRemember(ecPub) {
		t.Fatal("first sighting reported as replay")
	}
	time.Sleep(40 * time.Millisecond)
	if rc.checkAndRemember(ecPub) {
		t.Fatal("sighting after window expiry incorrectly reported as replay")
	}
}
