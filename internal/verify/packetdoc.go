package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// packetDoc is the part of packet.json the verifier reads. It is its own small copy of the shape (the verifier does
// not import the packet builder, so it can be installed alone), tolerant of added fields.
type packetDoc struct {
	Schema string `json:"schema"`
	Header struct {
		From   string                             `json:"from"`
		To     string                             `json:"to"`
		Scopes []string                           `json:"observation_scopes"`
		Named  bool                               `json:"scopes_named"`
		Filter struct{ App, Env, Cluster string } `json:"filter"`
		Chain  struct {
			Count    int64  `json:"count"`
			Head     string `json:"head"`
			FirstSeq int64  `json:"first_seq"`
			LastSeq  int64  `json:"last_seq"`
			Window   int    `json:"records_in_window"`
			Carried  int    `json:"records_carried"`
		} `json:"chain"`
	} `json:"header"`
	Coverage struct {
		Total      int `json:"total_records"`
		ByCoverage []struct {
			State string `json:"state"`
			Count int    `json:"count"`
		} `json:"by_coverage"`
		ByAssurance []struct {
			State string `json:"state"`
			Count int    `json:"count"`
		} `json:"by_assurance"`
		Matrix []struct {
			Coverage    string `json:"coverage"`
			Checkpoint  int    `json:"checkpointed"`
			Recorded    int    `json:"recorded_not_checkpointed"`
			NotRecorded int    `json:"not_recorded"`
			Total       int    `json:"total"`
		} `json:"coverage_by_assurance"`
	} `json:"coverage_statement"`
	Changes []struct {
		ID          string `json:"id"`
		Attestation *struct {
			Seq    int64  `json:"seq"`
			Digest string `json:"digest"`
			Bundle string `json:"bundle"`
		} `json:"attestation"`
	} `json:"changes"`
	Verification struct {
		Statement string `json:"statement"`
		Proofs    string `json:"proofs_file"`
		Ledger    struct {
			State           string `json:"state"`
			Origin          string `json:"origin"`
			Size            int64  `json:"size"`
			Root            string `json:"root"`
			CheckpointFile  string `json:"checkpoint_file"`
			Witnessed       bool   `json:"witnessed"`
			Checkpointed    int    `json:"records_checkpointed"`
			NotCheckpointed int    `json:"records_not_checkpointed"`
			ProofsCarried   int    `json:"proofs_carried"`
		} `json:"ledger"`
		Attestations        int      `json:"attestations_carried"`
		AttestationsMissing []string `json:"attestations_missing"`
	} `json:"verification"`
}

// loadPacket reads packet.json when there is one (the JSON presentation is optional in a packet, the evidence is not).
func (c *ctx) loadPacket() {
	raw, err := c.read(filePacket)
	if err != nil {
		c.rep.add(Check{Name: "packet.json", Status: NotChecked, Detail: "no packet.json to read the packet's own figures from (" + err.Error() + "); its counts and claims are not checked"})
		return
	}
	var p packetDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&p); err != nil {
		c.rep.add(Check{Name: "packet.json", Status: Fail, Detail: fmt.Sprintf("is not readable: %v", err)})
		return
	}
	if p.Schema != "clearance.packet/v1" {
		c.rep.add(Check{Name: "packet.json", Status: Fail, Detail: fmt.Sprintf("schema is %q, this verifier reads clearance.packet/v1", p.Schema)})
		return
	}
	c.pk = &p
}
