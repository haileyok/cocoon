package space

import "testing"

const (
	testDID        = "did:plc:z72i7hdynmk6r22z27h6tvur"
	testSpaceType  = "com.atproto.space"
	testSpaceKey   = "alpha"
	testCollection = "com.example.collection"
	testRecordKey  = "3jzfc"
)

func TestParseSpaceURIAndCanonicalRoundTrip(t *testing.T) {
	raw := "at://" + testDID + "/space/" + testSpaceType + "/" + testSpaceKey
	got, err := ParseSpaceURI(raw)
	if err != nil {
		t.Fatalf("ParseSpaceURI(%q): %v", raw, err)
	}
	if got.AuthorityDID.String() != testDID {
		t.Fatalf("authority DID = %q, want %q", got.AuthorityDID, testDID)
	}
	if got.SpaceType.String() != testSpaceType {
		t.Fatalf("space type = %q, want %q", got.SpaceType, testSpaceType)
	}
	if got.SKey.String() != testSpaceKey {
		t.Fatalf("space key = %q, want %q", got.SKey, testSpaceKey)
	}
	if got.String() != raw {
		t.Fatalf("String() = %q, want %q", got, raw)
	}
	again, err := ParseSpaceURI(got.String())
	if err != nil {
		t.Fatalf("canonical parse: %v", err)
	}
	if again != got {
		t.Fatalf("canonical parse changed value: %#v != %#v", again, got)
	}
}

func TestParseRecordURIAndCanonicalRoundTrip(t *testing.T) {
	raw := "at://" + testDID + "/space/" + testSpaceType + "/" + testSpaceKey + "/" + testDID + "/" + testCollection + "/" + testRecordKey
	got, err := ParseRecordURI(raw)
	if err != nil {
		t.Fatalf("ParseRecordURI(%q): %v", raw, err)
	}
	if got.String() != raw {
		t.Fatalf("String() = %q, want %q", got, raw)
	}
	if got.Space().String() != "at://"+testDID+"/space/"+testSpaceType+"/"+testSpaceKey {
		t.Fatalf("Space() = %q", got.Space())
	}
	again, err := ParseRecordURI(got.String())
	if err != nil {
		t.Fatalf("canonical parse: %v", err)
	}
	if again != got {
		t.Fatalf("canonical parse changed value: %#v != %#v", again, got)
	}
}

func TestURIParsersRejectInvalidVectors(t *testing.T) {
	spaceBase := "at://" + testDID + "/space/" + testSpaceType + "/" + testSpaceKey
	recordBase := spaceBase + "/" + testDID + "/" + testCollection + "/" + testRecordKey

	spaceInvalid := []string{
		"",
		"http://" + testDID + "/space/" + testSpaceType + "/" + testSpaceKey,
		"at://" + testDID + "/spaces/" + testSpaceType + "/" + testSpaceKey,
		spaceBase + "/extra",
		"at://" + testDID + "/space/" + testSpaceType,
		"at://did:plc:/space/" + testSpaceType + "/" + testSpaceKey,
		"at://" + testDID + "/space/com.example/" + testSpaceKey,
		"at://" + testDID + "/space/" + testSpaceType + "/.",
		spaceBase + "?query=1",
		spaceBase + "#fragment",
		"at://" + testDID + "/space/" + testSpaceType + "/%61lpha",
		"at://" + testDID + "/space/" + testSpaceType + "//" + testSpaceKey,
	}
	for _, raw := range spaceInvalid {
		if _, err := ParseSpaceURI(raw); err == nil {
			t.Errorf("ParseSpaceURI(%q) unexpectedly succeeded", raw)
		}
	}

	recordInvalid := []string{
		recordBase + "/extra",
		spaceBase + "/" + testDID + "/" + testCollection,
		"at://" + testDID + "/spaces/" + testSpaceType + "/" + testSpaceKey + "/" + testDID + "/" + testCollection + "/" + testRecordKey,
		spaceBase + "/did:plc:/" + testCollection + "/" + testRecordKey,
		spaceBase + "/" + testDID + "/com.example/" + testRecordKey,
		spaceBase + "/" + testDID + "/" + testCollection + "/..",
		recordBase + "?query=1",
		recordBase + "#fragment",
	}
	for _, raw := range recordInvalid {
		if _, err := ParseRecordURI(raw); err == nil {
			t.Errorf("ParseRecordURI(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestURIConstructorsValidateComponents(t *testing.T) {
	if _, err := NewSpaceURI(testDID, testSpaceType, testSpaceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRecordURI(testDID, testSpaceType, testSpaceKey, testDID, testCollection, testRecordKey); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSpaceURI("did:plc:", testSpaceType, testSpaceKey); err == nil {
		t.Error("NewSpaceURI accepted invalid authority DID")
	}
	if _, err := NewRecordURI(testDID, testSpaceType, testSpaceKey, testDID, "com.example", testRecordKey); err == nil {
		t.Error("NewRecordURI accepted invalid collection NSID")
	}
}

func TestSpaceScopeComponents(t *testing.T) {
	value, err := NewSpaceURI(testDID, testSpaceType, testSpaceKey)
	if err != nil {
		t.Fatal(err)
	}
	authority, spaceType, skey := value.SpaceScopeComponents()
	if authority != testDID || spaceType != testSpaceType || skey != testSpaceKey {
		t.Fatalf("SpaceScopeComponents() = %q, %q, %q", authority, spaceType, skey)
	}
}
