package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/gin-gonic/gin"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"math/big"
	"net/http"
)

func healthCheck(c *gin.Context) {
	response := gin.H{
		"status":  "ok",
		"message": "Health check passed",
	}

	c.JSON(http.StatusOK, response)
}

const fpSize = 4 * 8

func generateProof(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		var proofReq ProofRequest

		if err := c.ShouldBindJSON(&proofReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		proofWithPisVariable, pis := variables.DeserializeProofWithPublicInputs(proofReq.ProofWithPis)
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(proofReq.VerifierCircuitData)
		assignment := &verifier.VerifierCircuit{
			Proof:        proofWithPisVariable.Proof,
			VerifierData: verifierOnlyCircuitData,
			PublicInputs: proofWithPisVariable.PublicInputs,
		}

		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate witness: %v", err)})
			return
		}

		proof, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate proof: %v", err)})
			return
		}

		publicWitness, _ := witness.Public()
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to verify proof: %v", err)})
			return
		}

		buf := new(bytes.Buffer)
		proof.WriteRawTo(buf)
		proofBytes := buf.Bytes()

		proofs := make([]*big.Int, 8)

		for i := 0; i < 8; i++ {
			proofs[i] = new(big.Int).SetBytes(proofBytes[i*fpSize : (i+1)*fpSize])
		}

		jsonProofWithWitness, err := json.Marshal(struct {
			PublicInputs []uint64   `json:"inputs"`
			Proof        []*big.Int `json:"proof"`
		}{
			PublicInputs: pis,
			Proof:        proofs,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to marshal JSON: %v", err)})
			return
		}

		c.JSON(http.StatusOK, gin.H{"proofWithWitness": jsonProofWithWitness})
	}
}

type ProofRequest struct {
	ID                  string                           `json:"id"`
	ProofWithPis        types.ProofWithPublicInputsRaw   `json:"proofWithPis"`
	VerifierCircuitData types.VerifierOnlyCircuitDataRaw `json:"verifierData"`
}

func main() {
	path := "api-build"
	vk, _ := verifier.LoadGroth16VerifierKey(path)
	r1cs, pk, _ := verifier.LoadGroth16ProverData(path)
	//gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.GET("/health", healthCheck)
	router.POST("/proof", generateProof(r1cs, pk, vk))
	router.Run("localhost:8010")
}