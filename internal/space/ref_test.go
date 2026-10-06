package space

import "testing"

func TestParseRef(t *testing.T) {
	r, err := ParseRef("at://did:plc:asdf123/space/com.example.group/default")
	if err != nil || r.Authority != "did:plc:asdf123" || r.Type != "com.example.group" || r.Skey != "default" {
		t.Fatalf("%v %+v", err, r)
	}
	if r.String() != "at://did:plc:asdf123/space/com.example.group/default" {
		t.Fatal(r.String())
	}
	if r.RecordURI("did:plc:user1", "app.bsky.feed.post", "3jui7kd54zh2y") != "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/app.bsky.feed.post/3jui7kd54zh2y" {
		t.Fatal("record uri")
	}
	for _, bad := range []string{
		"at://user.test/space/com.example.group/default",
		"at://did:plc:asdf123/space/com.example.group",
		"at://did:plc:asdf123/notspace/com.example.group/default",
		"at://did:plc:asdf123/space/short/default",
		"at://did:plc:asdf123/space/com.example.group/a b",
		"did:plc:asdf123/space/com.example.group/default",
	} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
