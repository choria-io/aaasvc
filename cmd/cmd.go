package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin"
)

var (
	debug   bool
	Version = "development"
	cfile   string
	err     error
	pidfile string
	notls   bool

	ctx    context.Context
	cancel func()

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
	runcmd.Flag("disable-tls", "Disables TLS").Hidden().BoolVar(&notls)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	go interruptWatcher()

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

func interruptWatcher() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	select {
	case <-sigs:
		cancel()
	case <-ctx.Done():
		return
	}

}
