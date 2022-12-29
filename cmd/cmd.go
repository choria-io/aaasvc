package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/choria-io/fisk"
)

var (
	debug   bool
	Version = "development"
	cfile   string
	pidfile string
	notls   bool

	ctx    context.Context
	cancel func()
)

func Run() {
	app := fisk.New("caaa", "The Choria AAA Service")
	app.Author("R.I.Pienaar <rip@devco.net>")
	app.Version(Version)

	app.Command("crypt", "Encrypts a password received on STDIN using bcrypt").Action(crypt)

	runcmd := app.Command("run", "Starts the AAA Service").Action(run)
	runcmd.Flag("config", "Configuration to use").Required().PlaceHolder("FILE").ExistingFileVar(&cfile)
	runcmd.Flag("debug", "Enable debug logging").BoolVar(&debug)
	runcmd.Flag("pid", "File to write running pid to").StringVar(&pidfile)
	runcmd.Flag("disable-tls", "Disables TLS").Hidden().BoolVar(&notls)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	go interruptWatcher()

	app.MustParseWithUsage(os.Args[1:])
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
