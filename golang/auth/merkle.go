package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// The Merkle tree that control events use to commit to the content track
// (see sigchain-v2.md): RFC 6962 style, leaves are event hashes, a leaf is
// hashed as sha256(0x00 || leaf), an inner node as sha256(0x01 || left ||
// right), and a tree over n leaves splits at the largest power of two below n.

var emptyMerkleRoot = func() string { s := sha256.Sum256(nil); return hex.EncodeToString(s[:]) }()

func merkleLeaf(h []byte) []byte {
	s := sha256.Sum256(append([]byte{0}, h...))
	return s[:]
}

func merkleNode(left, right []byte) []byte {
	buf := make([]byte, 0, 1+len(left)+len(right))
	buf = append(buf, 1)
	buf = append(buf, left...)
	buf = append(buf, right...)
	s := sha256.Sum256(buf)
	return s[:]
}

// splitPoint is the largest power of two strictly less than n (n >= 2).
func splitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func merkleTree(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return merkleNode(merkleTree(leaves[:k]), merkleTree(leaves[k:]))
}

// MerkleRoot is the root (hex) over event hashes (hex).
func MerkleRoot(hashes []string) (string, error) {
	if len(hashes) == 0 {
		return emptyMerkleRoot, nil
	}
	leaves := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", errors.New("merkle: not a hex hash")
		}
		leaves[i] = merkleLeaf(b)
	}
	return hex.EncodeToString(merkleTree(leaves)), nil
}

// VerifyMerkleProof reports whether leaf sits at index of a tree of count
// leaves with the given root, given the audit path (hex siblings, leaf upwards).
// The tree size is bound by the signed commitment {count, root}, not by the root.
func VerifyMerkleProof(leaf string, index, count int, path []string, root string) bool {
	if index < 0 || index >= count {
		return false
	}
	leafBytes, err := hex.DecodeString(leaf)
	if err != nil {
		return false
	}
	siblings := make([][]byte, len(path))
	for i, p := range path {
		if siblings[i], err = hex.DecodeString(p); err != nil {
			return false
		}
	}
	var climb func(index, count int, siblings [][]byte) []byte
	climb = func(index, count int, siblings [][]byte) []byte {
		if count == 1 {
			if len(siblings) != 0 {
				return nil
			}
			return merkleLeaf(leafBytes)
		}
		if len(siblings) == 0 {
			return nil
		}
		k := splitPoint(count)
		rest, top := siblings[:len(siblings)-1], siblings[len(siblings)-1]
		if index < k {
			sub := climb(index, k, rest)
			if sub == nil {
				return nil
			}
			return merkleNode(sub, top)
		}
		sub := climb(index-k, count-k, rest)
		if sub == nil {
			return nil
		}
		return merkleNode(top, sub)
	}
	computed := climb(index, count, siblings)
	return computed != nil && hex.EncodeToString(computed) == root
}

func merklePath(leaves [][]byte, index int) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := splitPoint(len(leaves))
	if index < k {
		return append(merklePath(leaves[:k], index), merkleTree(leaves[k:]))
	}
	return append(merklePath(leaves[k:], index-k), merkleTree(leaves[:k]))
}

// MerkleProof is the audit path (hex siblings, leaf upwards) for the leaf at index.
func MerkleProof(hashes []string, index int) ([]string, error) {
	if index < 0 || index >= len(hashes) {
		return nil, errors.New("merkle: no such leaf")
	}
	leaves := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, errors.New("merkle: not a hex hash")
		}
		leaves[i] = merkleLeaf(b)
	}
	var out []string
	for _, p := range merklePath(leaves, index) {
		out = append(out, hex.EncodeToString(p))
	}
	return out, nil
}
