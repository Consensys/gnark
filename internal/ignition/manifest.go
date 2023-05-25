package ignition

import (
	"encoding/binary"
	"encoding/json"
	"time"
)

// NewManifest downloads and parses the manifest.json file
func NewManifest(config Config) (Manifest, error) {
	b, err := readOrDownload(config.ceremonyURL(), "manifest.json", config)
	if err != nil {
		return Manifest{}, err
	}

	var r Manifest
	err = json.Unmarshal(b, &r)
	if err != nil {
		return Manifest{}, err
	}

	return r, nil
}

// transcriptManifest is 28 bytes of data with the following structure
// byte index	description
// 0-3	transcript number (starting from 0)
// 4-7	total number of transcripts (should be 20)
// 8-11	total number of G1 points in all transcripts (should be 100,000,000)
// 12-15	total number of G2 points in all transcripts (should be 1)
// 16-19	number of G1 points in this transcript (should be 5,000,000)
// 20-23	number of G2 points in this transcript (2 for 1st transcript, 0 for the rest)
// 24-27	'start-from', the index of the 1st G1 point in this transcript
type transcriptManifest struct {
	TranscriptNumber,
	TotalTranscripts,
	TotalG1Points,
	TotalG2Points,
	NumG1Points,
	NumG2Points,
	StartFrom uint32
}

func newTranscriptManifest(data []byte) transcriptManifest {
	return transcriptManifest{
		TranscriptNumber: binary.BigEndian.Uint32(data[:4]),
		TotalTranscripts: binary.BigEndian.Uint32(data[4:8]),
		TotalG1Points:    binary.BigEndian.Uint32(data[8:12]),
		TotalG2Points:    binary.BigEndian.Uint32(data[12:16]),
		NumG1Points:      binary.BigEndian.Uint32(data[16:20]),
		NumG2Points:      binary.BigEndian.Uint32(data[20:24]),
		StartFrom:        binary.BigEndian.Uint32(data[24:28]),
	}
}

type Manifest struct {
	Name                string        `json:"name"`
	NumG1Points         int           `json:"numG1Points"`
	NumG2Points         int           `json:"numG2Points"`
	PointsPerTranscript int           `json:"pointsPerTranscript"`
	RangeProofKmax      int           `json:"rangeProofKmax"`
	RangeProofSize      int           `json:"rangeProofSize"`
	RangeProofsPerFile  int           `json:"rangeProofsPerFile"`
	Network             string        `json:"network"`
	SelectBlock         int           `json:"selectBlock"`
	StartTime           time.Time     `json:"startTime"`
	CompletedAt         time.Time     `json:"completedAt"`
	Participants        []Participant `json:"participants"`
	Crs                 struct {
		H  []string `json:"h"`
		T2 []string `json:"t2"`
	} `json:"crs"`
}

type Participant struct {
	Address     string    `json:"address"`
	Position    int       `json:"position"`
	StartedAt   time.Time `json:"startedAt"`
	CompletedAt time.Time `json:"completedAt"`
}
