package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/choria-io/fisk"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func crypt(_ *fisk.ParseContext) error {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		pass, err := bcrypt.GenerateFromPassword([]byte(scanner.Text()), 5)
		if err != nil {
			return errors.Wrap(err, "could not bcrypt password")
		}

		fmt.Println(string(pass))
	}

	if scanner.Err() != nil {
		return errors.Wrap(scanner.Err(), "reading STDIN failed")
	}

	return nil
}
