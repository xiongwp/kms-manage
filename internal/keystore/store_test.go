package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	k32hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	k24hex = "0102030405060708090a0b0c0d0e0f101112131415161718"
	k16hex = "0102030405060708090a0b0c0d0e0f10"
)

func writeKey(t *testing.T, dir, name, hex string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(hex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeActive(t *testing.T, dir, id string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ACTIVE"), []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_Happy(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "main.key", k32hex)
	writeKey(t, dir, "prev.key", k24hex)
	writeActive(t, dir, "main")

	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.ActiveKeyID() != "main" {
		t.Fatalf("active=%s", s.ActiveKeyID())
	}
	if _, ok := s.KeyByID("main"); !ok {
		t.Fatal("main missing")
	}
	if _, ok := s.KeyByID("prev"); !ok {
		t.Fatal("prev missing")
	}
	list := s.List()
	if len(list) != 2 || list[0].ID != "main" || list[1].ID != "prev" {
		t.Fatalf("list wrong: %+v", list)
	}
	main, _ := s.Meta("main")
	if main.Algorithm != "AES-256-GCM" {
		t.Fatalf("algo main: %s", main.Algorithm)
	}
	prev, _ := s.Meta("prev")
	if prev.Algorithm != "AES-192-GCM" {
		t.Fatalf("algo prev: %s", prev.Algorithm)
	}
}

func TestLoad_Empty(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("empty dir must fail")
	}
}

func TestLoad_NoActive(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "main.key", k32hex)
	if _, err := Load(dir); err == nil {
		t.Fatal("missing ACTIVE must fail")
	}
}

func TestLoad_ActivePointsNowhere(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "main.key", k32hex)
	writeActive(t, dir, "ghost")
	if _, err := Load(dir); err == nil {
		t.Fatal("ACTIVE → ghost must fail")
	}
}

func TestLoad_BadHex(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "main.key", "ZZZZ")
	writeActive(t, dir, "main")
	if _, err := Load(dir); err == nil {
		t.Fatal("bad hex must fail")
	}
}

func TestLoad_BadKeySize(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "main.key", "010203") // 3 bytes
	writeActive(t, dir, "main")
	if _, err := Load(dir); err == nil {
		t.Fatal("3-byte key must fail")
	}
}

func TestSnapshot_Independent(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "k.key", k16hex)
	writeActive(t, dir, "k")
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot()
	delete(snap, "k")
	if _, ok := s.KeyByID("k"); !ok {
		t.Fatal("modifying snapshot must not affect store")
	}
}
