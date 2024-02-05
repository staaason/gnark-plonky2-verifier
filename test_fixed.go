package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"math/big"
	"os"
	"time"
)

func reverseBytesSlice(slice []byte) {
	length := len(slice)
	for i := 0; i < length/2; i++ {
		slice[i], slice[length-i-1] = slice[length-i-1], slice[i]
	}
}

func main() {
	path := "api-build"
	fBaseDir := flag.String("plonky2-circuit", "testdata/test_circuit", "plonky2 circuit to benchmark")
	flag.Parse()
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(*fBaseDir + "/verifier_only_circuit_data.json"),
	)
	proofWithPis := types.ReadProofWithPublicInputs(*fBaseDir + "/proof_with_public_inputs.json")
	proofWithPisVariable, pis := variables.DeserializeProofWithPublicInputs(proofWithPis)
	var publicInputsConverted [4]frontend.Variable
	var bigIntPis [4]string
	for j := 0; j < 4; j++ {
		limbs := make([]byte, 16)
		slicePub := pis[j*4 : (j+1)*4]
		for i := 0; i < 4; i++ {
			offset := i * 4
			limbs[offset] = byte(slicePub[i] & 0xFF)
			limbs[offset+1] = byte((slicePub[i] >> 8) & 0xFF)
			limbs[offset+2] = byte((slicePub[i] >> 16) & 0xFF)
			limbs[offset+3] = byte((slicePub[i] >> 24) & 0xFF)
		}
		reverseBytesSlice(limbs)
		bigIntValue := new(big.Int).SetBytes(limbs)
		bigIntPis[j] = bigIntValue.String()
		publicInputsConverted[j] = frontend.Variable(bigIntValue)
	}
	assignment := &verifier.CircuitFixed{
		ProofWithPis: proofWithPisVariable,
		VerifierData: verifierOnlyCircuitData,
		PublicInputs: publicInputsConverted,
	}
	r1cs, pk, err := verifier.LoadGroth16ProverData(path)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("failed to generate witness: %w", err)
	}
	start := time.Now()
	proof, _ := groth16.Prove(r1cs, pk, witness)
	elapsed := time.Since(start)
	log.Info().Msg("Successfully created proof, time: " + elapsed.String())

	const fpSize = 4 * 8
	buf := new(bytes.Buffer)
	proof.WriteRawTo(buf)
	proofBytes := buf.Bytes()

	proofs := make([]string, 8)
	// Print out the proof
	for i := 0; i < 8; i++ {
		proofs[i] = new(big.Int).SetBytes(proofBytes[i*fpSize : (i+1)*fpSize]).String()
	}

	jsonProofWithWitness, err := json.Marshal(struct {
		PublicInputs [4]string `json:"inputs"`
		Proof        []string  `json:"proof"`
	}{
		PublicInputs: bigIntPis,
		Proof:        proofs,
	})
	if err != nil {
		fmt.Printf("failed to marshal proof with witness: %w", err)
	}
	proofFile, err := os.Create("proof_with_witness_fixed.json")
	if err != nil {
		fmt.Printf("failed to create proof_with_witness file: %w", err)
	}
	_, err = proofFile.Write(jsonProofWithWitness)
	if err != nil {
		fmt.Printf("failed to write proof_with_witness file: %w", err)
	}
	proofFile.Close()
	log.Debug().Msg("Successfully saved proof_with_witness")
}
