package cmd

import (
	"fmt"
	"os"

	"github.com/alecthomas/kingpin"
)

var (
	debug   bool
	Version = "development"
	cfile   string
	err     error
	pidfile string

	runcmd   *kingpin.CmdClause
	cryptcmd *kingpin.CmdClause
)

func Run() {
	app := kingpin.New("caaa", "The Choria AAA Service")
	app.Author("R.I.Pienaar <rip@devco.net>")
	app.Version(Version)
	cryptcmd = app.Command("crypt", "Encrypts a password received on STDIN using bcrypt")

	runcmd = app.Command("run", "Starts the AAA Service")
	runcmd.Flag("config", "Configuration to use").Required().ExistingFileVar(&cfile)
	runcmd.Flag("debug", "Enable debug logging").BoolVar(&debug)
	runcmd.Flag("pid", "File to write running pid to").StringVar(&pidfile)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	if command == cryptcmd.FullCommand() {
		err = crypt()
		kingpin.FatalIfError(err, "could not run: %s", err)
		return
	}

	switch command {
	case cryptcmd.FullCommand():
		err = crypt()
	case runcmd.FullCommand():
		err = run()
	default:
		err = fmt.Errorf("unknown command: %s", command)
	}

	kingpin.FatalIfError(err, "could not run")
}
