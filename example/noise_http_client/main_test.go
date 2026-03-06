package main

import (
	"bytes"
	"testing"
)

func TestParseNoiseProtocol(t *testing.T) {
	spec, err := parseNoiseProtocol("Noise_NK_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		t.Fatalf("parseNoiseProtocol returned error: %v", err)
	}

	if spec.Header.VersionID != noiseVersionID {
		t.Fatalf("unexpected version id: got %d want %d", spec.Header.VersionID, noiseVersionID)
	}
	if spec.Header.DHID != noiseDHCurve25519ID {
		t.Fatalf("unexpected dh id: got %d want %d", spec.Header.DHID, noiseDHCurve25519ID)
	}
	if spec.Header.CipherID != noiseCipherChaChaPolyID {
		t.Fatalf("unexpected cipher id: got %d want %d", spec.Header.CipherID, noiseCipherChaChaPolyID)
	}
	if spec.Header.HashID != noiseHashBLAKE2sID {
		t.Fatalf("unexpected hash id: got %d want %d", spec.Header.HashID, noiseHashBLAKE2sID)
	}
	if spec.Header.PatternID != noisePatternNKID {
		t.Fatalf("unexpected pattern id: got %d want %d", spec.Header.PatternID, noisePatternNKID)
	}
}

func TestParseNoiseProtocolRejectsUnsupportedPattern(t *testing.T) {
	if _, err := parseNoiseProtocol("Noise_XX_25519_AESGCM_BLAKE2b"); err == nil {
		t.Fatal("parseNoiseProtocol unexpectedly accepted unsupported pattern XX")
	}
}

func TestBuildNoisePrologueUsesConfiguredText(t *testing.T) {
	spec, err := parseNoiseProtocol("Noise_NK_25519_AESGCM_SHA256")
	if err != nil {
		t.Fatalf("parseNoiseProtocol returned error: %v", err)
	}

	got, err := buildNoisePrologue("NoiseSocketInit2", spec.Header)
	if err != nil {
		t.Fatalf("buildNoisePrologue returned error: %v", err)
	}

	want := append([]byte("NoiseSocketInit2"), 0x00, noiseNegotiationLen)
	want = append(want,
		0x00, noiseVersionID,
		noiseDHCurve25519ID,
		noiseCipherAESGCMID,
		noiseHashSHA256ID,
		noisePatternNKID,
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected prologue bytes: got %x want %x", got, want)
	}
}

func TestBuildInitiatorHandshakeConfigForNK(t *testing.T) {
	spec, err := parseNoiseProtocol("Noise_NK_25519_AESGCM_SHA512")
	if err != nil {
		t.Fatalf("parseNoiseProtocol returned error: %v", err)
	}

	serverPublicKey := bytes.Repeat([]byte{0x42}, noiseKeySize)
	config, err := buildInitiatorHandshakeConfig(spec, "NoiseSocketInit1", serverPublicKey)
	if err != nil {
		t.Fatalf("buildInitiatorHandshakeConfig returned error: %v", err)
	}

	if len(config.StaticKeypair.Private) != 0 {
		t.Fatalf("unexpected local static private key length: got %d want 0", len(config.StaticKeypair.Private))
	}
	if !bytes.Equal(config.PeerStatic, serverPublicKey) {
		t.Fatalf("unexpected peer static key: got %x want %x", config.PeerStatic, serverPublicKey)
	}
}
