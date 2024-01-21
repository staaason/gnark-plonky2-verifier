package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog/log"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"math/big"
	"os"
	"time"
)

func runBenchmarkPatricia(build_path string, proofSystem string) {
	dirPath := "testdata"
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}

	excludeDirs := map[string]struct{}{
		"decode_block":           {},
		"receipt_6_circuit_data": {},
		"state_circuit_data":     {},
		"step":                   {},
		"test_circuit":           {},
	}

	for _, entry := range entries {
		if entry.IsDir() {
			dirName := entry.Name()
			if _, excluded := excludeDirs[dirName]; !excluded {
				circuit_path := dirPath + "/" + dirName
				if proofSystem == "plonk" {
					start := time.Now()
					start_full := time.Now()
					verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
						types.ReadVerifierOnlyCircuitData(circuit_path + "/verifier_only_circuit_data.json"),
					)
					proofWithPis := types.ReadProofWithPublicInputs(circuit_path + "/proof_with_public_inputs.json")
					proofWithPisVariable, pis := variables.DeserializeProofWithPublicInputs(proofWithPis)
					assignment := &verifier.VerifierCircuit{
						Proof:        proofWithPisVariable.Proof,
						VerifierData: verifierOnlyCircuitData,
						PublicInputs: proofWithPisVariable.PublicInputs,
					}
					r1cs, pk, err := verifier.LoadPlonkProverData(build_path)
					if err != nil {
						fmt.Printf("error: %s\n", err.Error())
					}
					elapsed := time.Since(start)
					log.Info().Msg("Successfully loaded proof and plonk prover data, time: " + elapsed.String())
					start = time.Now()
					witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
					if err != nil {
						fmt.Printf("failed to generate witness: %w", err)
					}
					elapsed = time.Since(start)
					log.Info().Msg("Successfully generated witness, time: " + elapsed.String())

					log.Info().Msg("Creating proof")
					start = time.Now()
					proof, err := plonk.Prove(r1cs, pk, witness)
					if err != nil {
						fmt.Printf("failed to create proof: %w", err)
					}
					elapsed_full := time.Since(start_full)
					log.Info().Msg("Full proving time: " + elapsed_full.String())
					elapsed = time.Since(start)
					log.Info().Msg("Successfully created proof, time: " + elapsed.String())
					_proof := proof.(*plonk_bn254.Proof)
					log.Info().Msg("Saving proof to proof.json")
					serializedProof := _proof.MarshalSolidity()
					log.Printf("Proof len: %d", len(serializedProof))
					jsonProofWithWitness, err := json.Marshal(struct {
						PublicInputs []uint64      `json:"inputs"`
						Proof        hexutil.Bytes `json:"proof"`
					}{
						PublicInputs: pis,
						Proof:        serializedProof,
					})
					if err != nil {
						fmt.Printf("failed to marshal proof with witness: %w", err)
					}
					proofFile, err := os.Create("proof_with_witness.json")
					if err != nil {
						fmt.Printf("failed to create proof_with_witness file: %w", err)
					}
					_, err = proofFile.Write(jsonProofWithWitness)
					if err != nil {
						fmt.Printf("failed to write proof_with_witness file: %w", err)
					}
					proofFile.Close()
					log.Info().Msg("Successfully saved proof_with_witness")
					start_verify := time.Now()
					publicWitness, _ := witness.Public()
					vk, _ := verifier.LoadPlonkVerifierKey(build_path)
					err = plonk.Verify(proof, vk, publicWitness)
					elapsed = time.Since(start_verify)

					log.Info().Msg("Verify proof, time: " + elapsed.String())

				} else if proofSystem == "groth16" {
					start_full := time.Now()
					verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
						types.ReadVerifierOnlyCircuitData(circuit_path + "/verifier_only_circuit_data.json"),
					)
					proofWithPis := types.ReadProofWithPublicInputs(circuit_path + "/proof_with_public_inputs.json")
					proofWithPisVariable, pis := variables.DeserializeProofWithPublicInputs(proofWithPis)
					assignment := &verifier.VerifierCircuit{
						Proof:        proofWithPisVariable.Proof,
						VerifierData: verifierOnlyCircuitData,
						PublicInputs: proofWithPisVariable.PublicInputs,
					}
					r1cs, pk, err := verifier.LoadGroth16ProverData(build_path)
					if err != nil {
						fmt.Printf("error: %s\n", err.Error())
					}
					witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
					if err != nil {
						fmt.Printf("failed to generate witness: %w", err)
					}
					start := time.Now()
					proof, _ := groth16.Prove(r1cs, pk, witness)
					elapsed_full := time.Since(start_full)
					log.Info().Msg("Full proving time: " + elapsed_full.String())
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
						PublicInputs []uint64 `json:"inputs"`
						Proof        []string `json:"proof"`
					}{
						PublicInputs: pis,
						Proof:        proofs,
					})
					if err != nil {
						fmt.Printf("failed to marshal proof with witness: %w", err)
					}
					proofFile, err := os.Create("proof_with_witness.json")
					if err != nil {
						fmt.Printf("failed to create proof_with_witness file: %w", err)
					}
					_, err = proofFile.Write(jsonProofWithWitness)
					if err != nil {
						fmt.Printf("failed to write proof_with_witness file: %w", err)
					}
					proofFile.Close()
					log.Debug().Msg("Successfully saved proof_with_witness")
					start_verify := time.Now()
					publicWitness, _ := witness.Public()
					vk, _ := verifier.LoadGroth16VerifierKey(build_path)
					err = groth16.Verify(proof, vk, publicWitness)
					elapsed = time.Since(start_verify)
					log.Info().Msg("Verify proof, time: " + elapsed.String())
				}
			}
		}
	}
}

func main() {
	plonky2Circuit := flag.String("build-dir", "build", "patricia plonky2 build to benchmark")
	proofSystem := flag.String("proof-system", "plonk", "proof system to benchmark")
	flag.Parse()
	fmt.Printf("Running benchmark for %s circuit with proof system %s\n", *plonky2Circuit, *proofSystem)

	runBenchmarkPatricia(*plonky2Circuit, *proofSystem)
}
