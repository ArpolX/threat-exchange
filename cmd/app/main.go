package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"threat-exchange/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := app.Run(ctx)
	stop()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "threat exchange service failed: %v\n", err)
		os.Exit(1)
	}
}
