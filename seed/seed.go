package seed

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/aezeed"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	numberDotsRegex = regexp.MustCompile(`[\d.\-\n\r\t]*`)
	multipleSpaces  = regexp.MustCompile(" [ ]+")
)

// ReadAezeed reads an aezeed from the console or the environment variable.
func ReadAezeed(params *chaincfg.Params) (*hdkeychain.ExtendedKey, time.Time,
	error) {
	mnemonicStr := ""

	// If nothing is set in the environment, read the seed from the
	// terminal.
	if mnemonicStr == "" {
		var err error
		// We'll now prompt the user to enter in their 24-word mnemonic.
		fmt.Printf("Input your 24-word mnemonic separated by spaces: ")
		reader := bufio.NewReader(os.Stdin)
		mnemonicStr, err = reader.ReadString('\n')
		if err != nil {
			return nil, time.Unix(0, 0), err
		}
	}

	// We'll trim off extra spaces, and ensure the mnemonic is all
	// lower case.
	mnemonicStr = strings.TrimSpace(mnemonicStr)
	mnemonicStr = strings.ToLower(mnemonicStr)

	// To allow the tool to also accept the copy/pasted version of the
	// backup text (which contains numbers and dots and multiple spaces),
	// we do some more cleanup with regex.
	mnemonicStr = numberDotsRegex.ReplaceAllString(mnemonicStr, "")
	mnemonicStr = multipleSpaces.ReplaceAllString(mnemonicStr, " ")
	mnemonicStr = strings.TrimSpace(mnemonicStr)

	cipherSeedMnemonic := strings.Split(mnemonicStr, " ")

	fmt.Println()

	if len(cipherSeedMnemonic) != 24 {
		return nil, time.Unix(0, 0), fmt.Errorf("wrong cipher seed "+
			"mnemonic length: got %v words, expecting %v words",
			len(cipherSeedMnemonic), 24)
	}

	passphraseBytes, err := ReadPassphrase("doesn't have")
	if err != nil {
		return nil, time.Unix(0, 0), err
	}

	var mnemonic aezeed.Mnemonic
	copy(mnemonic[:], cipherSeedMnemonic)

	// If we're unable to map it back into the ciphertext, then either the
	// mnemonic is wrong, or the passphrase is wrong.
	cipherSeed, err := mnemonic.ToCipherSeed(passphraseBytes)
	if err != nil {
		return nil, time.Unix(0, 0), fmt.Errorf("failed to decrypt "+
			"seed with passphrase: %w", err)
	}
	rootKey, err := hdkeychain.NewMaster(cipherSeed.Entropy[:], params)
	if err != nil {
		return nil, time.Unix(0, 0), errors.New("failed to derive " +
			"master extended key")
	}
	return rootKey, cipherSeed.BirthdayTime(), nil
}

// ReadPassphrase reads a cipher seed passphrase from the console or the
// environment variable.
func ReadPassphrase(verb string) ([]byte, error) {
	passphrase := ""

	// Because we cannot differentiate between an empty and a non-existent
	// environment variable, we need a special character that indicates that
	// no passphrase should be used. We use a single dash (-) for that as
	// that would be too short for a passphrase anyway.
	var passphraseBytes []byte
	switch {
	// The user indicated in the environment variable that no passphrase
	// should be used. We don't set any value.
	case passphrase == "-":

	// The environment variable didn't contain anything, we'll read the
	// passphrase from the terminal.
	case passphrase == "":
		fmt.Printf("Input your cipher seed passphrase (press enter "+
			"if your seed %s a passphrase): ", verb)
		var err error
		passphraseBytes, err = terminal.ReadPassword(
			int(syscall.Stdin), //nolint
		)
		if err != nil {
			return nil, err
		}
		fmt.Println()

	// There was a password in the environment, just convert it to bytes.
	default:
		passphraseBytes = []byte(passphrase)
	}

	return passphraseBytes, nil
}
