package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	gozuul "github.com/adevinta/gozuul"

	"github.com/spf13/cobra"
)

// passiveCmd represents the passive command
var passiveCmd = &cobra.Command{
	Use:   "passive <target>...",
	Short: "Executes a new passive scan against the specified targets",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("incorrect number of args, want 1 at least, got %v", len(args))
		}

		targets := args[0:]

		passiveScan(targets...)

		return nil
	},
}

// passiveBulkCmd represents the passivebulk command
var passiveBulkCmd = &cobra.Command{
	Use:   "passivebulk <targets-file>",
	Short: "Executes a new passive scan against the targets specified in a file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("incorrect number of args, want 1, got %v", len(args))
		}

		tf := args[0]

		targets, err := readLines(tf)
		if err != nil {
			return err
		}

		passiveScan(targets...)

		return nil
	},
}

func init() {
	RootCmd.AddCommand(passiveCmd)
	RootCmd.AddCommand(passiveBulkCmd)
}

func passiveScan(targets ...string) {
	vulnerable := make(chan string, len(targets))
	errors := make(chan error, len(targets))
	done := make(chan bool)

	go func() {
		var wg sync.WaitGroup
		rate := make(chan struct{}, 30)

		for _, target := range targets {
			rate <- struct{}{}
			wg.Add(1)

			go func(target string) {
				defer func() {
					<-rate
					wg.Done()
				}()

				t := target

				rs, err := gozuul.PassiveScan(t)
				if err != nil {
					errors <- err
				} else if rs.Vulnerable {
					vulnerable <- t
				}
			}(target)
		}

		wg.Wait()
		done <- true

	}()

loop:
	for {
		select {
		case target := <-vulnerable:
			fmt.Printf("%v is vulnerable\n", target)
		case err := <-errors:
			if verbose {
				fmt.Println(err)
			}
		case <-done:
			break loop
		}
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
