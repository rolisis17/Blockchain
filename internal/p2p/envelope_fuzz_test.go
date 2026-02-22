package p2p

import (
	"encoding/json"
	"testing"
)

func FuzzExtractMessageMeta(f *testing.F) {
	f.Add([]byte(`{"type":"block_vote","senderId":"v1","payload":{"height":2,"blockHash":"h2","voterId":"v1","approve":true,"timestamp":1700000002000},"signature":"00"}`))
	f.Add([]byte(`{"type":"block_proposal","senderId":"v2","payload":{"block":{"height":3,"round":0,"prevHash":"h2","timestamp":1700000003000,"proposer":"v2","transactions":[],"stateRoot":"root","hash":"h3","votes":[],"finalized":false}},"signature":"11"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return
		}
		_, _ = extractMessageMeta(env)
		switch env.Type {
		case MessageTypeBlockProposal:
			_, _ = decodeStrict[BlockProposal](env.Payload)
		case MessageTypeBlockVote:
			_, _ = decodeStrict[BlockVote](env.Payload)
		case MessageTypeBlockFinalize:
			_, _ = decodeStrict[BlockFinalize](env.Payload)
		}
	})
}
