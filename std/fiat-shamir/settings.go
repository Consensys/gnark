package fiatshamir

import (
	"math/big"
	gohash "hash"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
)

type Settings struct {
	Transcript     *Transcript
	Prefix         string
	BaseChallenges []big.Int
	Hash           gohash.Hash
}

type SettingsEmulated[FR emulated.FieldParams] struct {
	Transcript     *Transcript
	Prefix         string
	BaseChallenges []emulated.Element[FR]
	Hash           hash.FieldHasher
}

func WithTranscript(transcript *Transcript, prefix string, baseChallenges ...big.Int) Settings {
	return Settings{
		Transcript:     transcript,
		Prefix:         prefix,
		BaseChallenges: baseChallenges,
	}
}

func WithTranscriptFr[FR emulated.FieldParams](transcript *Transcript, prefix string, baseChallenges ...emulated.Element[FR]) SettingsEmulated[FR] {
	return SettingsEmulated[FR]{
		Transcript:     transcript,
		Prefix:         prefix,
		BaseChallenges: baseChallenges,
	}
}

func WithHash(hash gohash.Hash, baseChallenges ...big.Int) Settings {
	return Settings{
		BaseChallenges: baseChallenges,
		Hash:           hash,
	}
}

func WithHashFr[FR emulated.FieldParams](hash hash.FieldHasher, baseChallenges ...emulated.Element[FR]) SettingsEmulated[FR] {
	return SettingsEmulated[FR]{
		BaseChallenges: baseChallenges,
		Hash:           hash,
	}
}