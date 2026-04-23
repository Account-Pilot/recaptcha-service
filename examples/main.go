package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Account-Pilot/recaptcha-service"
	"github.com/Account-Pilot/recaptcha-service/anticaptcha"
	"github.com/Account-Pilot/recaptcha-service/capsolver"
	"github.com/Account-Pilot/recaptcha-service/custom"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	targetURL := "https://volatix.io/login"
	siteKey := "6Lda_posAAAAAHnjENcIafEQIS88K2FIzWNoaxwl"
	action := "login"
	captchaType := recaptcha.V3Enterprise

	solvers := map[string]recaptcha.Solver{}

	if key := os.Getenv("ANTICAPTCHA_KEY"); key != "" {
		solvers["anticaptcha"] = anticaptcha.New(key, siteKey)
	}
	if key := os.Getenv("CAPSOLVER_KEY"); key != "" {
		solvers["capsolver"] = capsolver.New(key, siteKey)
	}
	if key := os.Getenv("VOLATILE_KEY"); key != "" {
		solvers["custom"] = custom.New(key, siteKey)
	}

	if len(solvers) == 0 {
		log.Fatal("set at least one of ANTICAPTCHA_KEY, CAPSOLVER_KEY, VOLATILE_KEY")
	}

	for name, s := range solvers {
		token, err := s.Solve(ctx, targetURL, captchaType, action)
		if err != nil {
			fmt.Printf("%s: %v\n", name, err)
			continue
		}
		fmt.Printf("%s: %s\n", name, token)
	}
}
