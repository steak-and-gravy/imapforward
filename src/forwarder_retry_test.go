package main

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

func TestForwarderFailedUIDRetriesBeforeMarkingForwarded(t *testing.T) {
	backend := imapmemserver.New()
	user := imapmemserver.NewUser("test", "test")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	backend.AddUser(user)
	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return backend.NewSession(), nil, nil
		},
		InsecureAuth: true, // Loopback test server only.
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client := imapclient.New(conn, nil)
	defer func() { _ = client.Close() }()
	if err := client.Login("test", "test").Wait(); err != nil {
		t.Fatal(err)
	}
	raw := []byte("Message-ID: <original@example.com>\r\n\r\nbody")
	appendCmd := client.Append("INBOX", int64(len(raw)), nil)
	if _, err := appendCmd.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatal(err)
	}
	appended, err := appendCmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	sender := &mockSender{err: testError("simulated Gmail rejection")}
	forwarder := NewForwarder(SourceConfig{Name: "test"}, sender, nil)
	ctx := context.Background()
	if err := forwarder.forwardNewMessages(ctx, client); err != nil {
		t.Fatal(err)
	}
	eligible, err := client.UIDSearch(&imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen, imap.Flag(forwardedFlag)}}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if uids := eligible.AllUIDs(); len(uids) != 1 || uids[0] != appended.UID {
		t.Fatal("failed UID was skipped or marked as seen/forwarded")
	}
	sender.err = nil
	if err := forwarder.forwardNewMessages(ctx, client); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 || !bytes.Equal(sender.sent[0], raw) {
		t.Fatal("failed UID was not retried with the original raw message")
	}
	forwarded, err := client.UIDSearch(&imap.SearchCriteria{Flag: []imap.Flag{imap.Flag(forwardedFlag)}}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if uids := forwarded.AllUIDs(); len(uids) != 1 || uids[0] != appended.UID {
		t.Fatal("successful UID was not marked forwarded")
	}
	if err := forwarder.forwardNewMessages(ctx, client); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatal("successfully forwarded UID was imported again")
	}
}
