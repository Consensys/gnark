package fiatshamir

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
)

type Settings struct {
	Transcript     *Transcript
	Prefix         string
	BaseChallenges []frontend.Variable
	Hash           hash.FieldHasher
}

type SettingsEmulated[FR emulated.FieldParams] struct {
	Transcript     *Transcript
	Prefix         string
	BaseChallenges []emulated.Element[FR]
	Hash           hash.FieldHasher
}

func WithTranscript(transcript *Transcript, prefix string, baseChallenges ...frontend.Variable) Settings {
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

func WithHash(hash hash.FieldHasher, baseChallenges ...frontend.Variable) Settings {
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