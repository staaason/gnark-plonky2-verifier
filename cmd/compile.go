package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

var (
	system string
)

var compileCmd = &cobra.Command{
	Use:   "compile",
	Short: "compile build circuit data(pv, vk, solidity contract) from plonky2 proof",
	Run:   compile,
}

func compile(cmd *cobra.Command, args []string) {
	err := verifier.CompileVerifierCircuit(fBaseDir, system)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
	}
}

func init() {
	rootCmd.AddCommand(compileCmd)
	compileCmd.Flags().StringVar(&system, "system", "plonk", "proof system for proving (groth16 or plonk)")
}
